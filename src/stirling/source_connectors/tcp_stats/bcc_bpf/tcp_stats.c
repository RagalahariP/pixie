/*
* This code runs using bpf in the Linux kernel.
* Copyright 2018- The Pixie Authors.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*
* SPDX-License-Identifier: GPL-2.0
*/

// LINT_C_FILE: Do not remove this line. It ensures cpplint treats this as a C file.

#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include "src/stirling/source_connectors/tcp_stats/bcc_bpf_intf/tcp_stats.h"
#include "src/stirling/bpf_tools/bcc_bpf/utils.h"


#define MAXARG 10

// Map to indicate number of TCP bytes sent.
// Key is {remoteIP & process name} */
BPF_HASH(sent_bytes, struct ip_key_t);
// Map to indicate number of TCP bytes received.
// Key is {remoteIP & process name} */
BPF_HASH(recv_bytes, struct ip_key_t);

// Map to indicate number of TCP retransmissions.
// Key is {remoteIP & process name}
BPF_HASH(retrans, struct ip_key_t);

// Map to store TCP socket information.
// Key is {tid}.
BPF_HASH(sock_store, u32, struct sock *);

BPF_PERF_OUTPUT(events);

// Map to indicate TCP Latency.
// Key is {remoteIP & port}.
BPF_HASH(latency, struct latency_key_t, struct sock_latency_t);

BPF_HISTOGRAM(latency_histogram, struct socket_key_t);

static int tcp_sendstat(int size) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 tid = bpf_get_current_pid_tgid();
  struct sock **sockpp;
  sockpp = sock_store.lookup(&tid);
  if (sockpp == 0) {
    return 0;  // entry missed
  }

  struct sock *sk = *sockpp;
  struct sock_common* sk_common = &sk->__sk_common;
  uint16_t family = -1;
  uint16_t port = -1;

  BPF_PROBE_READ_KERNEL_VAR(port, &sk_common->skc_dport);
  BPF_PROBE_READ_KERNEL_VAR(family, &sk_common->skc_family);

  struct ip_key_t ip_key = {};
  ip_key.addr.sa.sa_family = family;

  if (family == AF_INET) {
    ip_key.addr.in4.sin_port = ntohs(port);
    BPF_PROBE_READ_KERNEL_VAR(ip_key.addr.in4.sin_addr.s_addr, &sk_common->skc_daddr);
  } else if (family == AF_INET6) {
    ip_key.addr.in6.sin6_port = ntohs(port);
    BPF_PROBE_READ_KERNEL_VAR(ip_key.addr.in6.sin6_addr, &sk_common->skc_v6_daddr);
  }

  bpf_get_current_comm(&ip_key.name, sizeof(ip_key.name));
  sent_bytes.increment(ip_key, size);

  sock_store.delete(&tid);
  return 0;
}

int probe_ret_tcp_sendmsg(struct pt_regs *ctx) {
  int size = PT_REGS_RC(ctx);
  if (size > 0)
    return tcp_sendstat(size);
  else
    return 0;
}

int probe_ret_tcp_sendpage(struct pt_regs *ctx) {
  int size = PT_REGS_RC(ctx);
  if (size > 0)
    return tcp_sendstat(size);
  else
    return 0;
}

static int tcp_send_entry(struct sock *sk) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 tid = bpf_get_current_pid_tgid();
  sock_store.update(&tid, &sk);
  return 0;
}

int probe_entry_tcp_sendpage(struct pt_regs *ctx, struct sock *sk,
                             struct page *page, int offset, size_t size) {
  return tcp_send_entry(sk);
}

int probe_entry_tcp_sendmsg(struct pt_regs* ctx, struct sock *sk,
                            struct msghdr *msg, size_t size) {
  return tcp_send_entry(sk);
}

int probe_entry_tcp_cleanup_rbuf(struct pt_regs* ctx, struct sock *sk,
                                 int copied) {
  if (copied <= 0)
    return 0;

  uint16_t family = -1;
  uint16_t port = -1;

  BPF_PROBE_READ_KERNEL_VAR(port, &sk->__sk_common.skc_dport);
  BPF_PROBE_READ_KERNEL_VAR(family, &sk->__sk_common.skc_family);

  struct ip_key_t ip_key = {};
  ip_key.addr.sa.sa_family = family;

  bpf_get_current_comm(&ip_key.name, sizeof(ip_key.name));
  if (family == AF_INET) {
    ip_key.addr.in4.sin_port = ntohs(port);
    BPF_PROBE_READ_KERNEL_VAR(ip_key.addr.in4.sin_addr.s_addr, &sk->__sk_common.skc_daddr);
  } else if (family == AF_INET6) {
    ip_key.addr.in6.sin6_port = ntohs(port);
    BPF_PROBE_READ_KERNEL_VAR(ip_key.addr.in6.sin6_addr, &sk->__sk_common.skc_v6_daddr);
  }
  recv_bytes.increment(ip_key, copied);
  return 0;
}


int probe_entry_tcp_retransmit_skb(struct pt_regs *ctx, struct sock *skp, struct sk_buff *skb, int type) {
  if (skp == NULL)
    return 0;

  uint16_t family = -1;
  uint16_t port = -1;

  BPF_PROBE_READ_KERNEL_VAR(port, &skp->__sk_common.skc_dport);
  BPF_PROBE_READ_KERNEL_VAR(family, &skp->__sk_common.skc_family);

  struct ip_key_t ip_key = {};
  ip_key.addr.sa.sa_family = family;

  bpf_get_current_comm(&ip_key.name, sizeof(ip_key.name));
  if (family == AF_INET) {
    ip_key.addr.in4.sin_port = ntohs(port);
    BPF_PROBE_READ_KERNEL_VAR(ip_key.addr.in4.sin_addr.s_addr, &skp->__sk_common.skc_daddr);
  } else if (family == AF_INET6) {
    ip_key.addr.in6.sin6_port = ntohs(port);
    BPF_PROBE_READ_KERNEL_VAR(ip_key.addr.in6.sin6_addr, &skp->__sk_common.skc_v6_daddr);
  }
  retrans.increment(ip_key, 1);
  return 0;
}


int probe_entry_tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
  struct tcp_sock *ts = tcp_sk(sk);
  u32 srtt = (ts->srtt_us >> 3) / 1000 ;

  //bpf_trace_printk("ts->srtt_us >> 3 %u ", ts->srtt_us >> 3); 
  uint16_t family = -1;
  uint16_t dport = -1;
  uint16_t sport = -1;

  BPF_PROBE_READ_KERNEL_VAR(dport, &sk->__sk_common.skc_dport);
  BPF_PROBE_READ_KERNEL_VAR(family, &sk->__sk_common.skc_family);
  BPF_PROBE_READ_KERNEL_VAR(sport, &sk->__sk_common.skc_num);
  struct latency_key_t latency_key = {};
  struct socket_key_t sock_key = {};
  
  latency_key.saddr.sa.sa_family = family;
  latency_key.daddr.sa.sa_family = family;

  sock_key.daddr.sa.sa_family = family;

  if (family == AF_INET) {
    latency_key.daddr.in4.sin_port = ntohs(dport);
    latency_key.saddr.in4.sin_port = sport;
    BPF_PROBE_READ_KERNEL_VAR(latency_key.daddr.in4.sin_addr.s_addr, &sk->__sk_common.skc_daddr);
    BPF_PROBE_READ_KERNEL_VAR(latency_key.saddr.in4.sin_addr.s_addr, &sk->__sk_common.skc_rcv_saddr);
    sock_key.daddr.in4.sin_port = ntohs(dport);
    BPF_PROBE_READ_KERNEL_VAR(sock_key.daddr.in4.sin_addr.s_addr, &sk->__sk_common.skc_daddr);
  } else if (family == AF_INET6) {
    latency_key.daddr.in6.sin6_port = ntohs(dport);
    latency_key.saddr.in6.sin6_port = sport;
    BPF_PROBE_READ_KERNEL_VAR(latency_key.daddr.in6.sin6_addr, &sk->__sk_common.skc_v6_daddr);
    BPF_PROBE_READ_KERNEL_VAR(latency_key.saddr.in6.sin6_addr, &sk->__sk_common.skc_v6_rcv_saddr);
    sock_key.daddr.in6.sin6_port = ntohs(dport);
    BPF_PROBE_READ_KERNEL_VAR(sock_key.daddr.in6.sin6_addr, &sk->__sk_common.skc_v6_daddr);
  }

  struct sock_latency_t newlat = {0};
  struct sock_latency_t *lat;
  lat = latency.lookup(&latency_key);
  if (lat != NULL) {
      newlat.latency += srtt ;
      newlat.count += 1; 
      latency.update(&latency_key, &newlat);
  } else {
       lat->latency +=srtt;
       lat->count += 1;
  }
 
  sock_key.slot = bpf_log2l(srtt);
  latency_histogram.atomic_increment(sock_key);
  return 0; 
}

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}
static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__probe_entry_execv(struct pt_regs* ctx,
                               const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp ) {
   //bpf_trace_printk("I am here in entry");
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;
    __submit_arg(ctx, (void *)filename, &data);
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        //bpf_trace_printk("argv[i] %s", __argv[i]);
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             return 0;
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
    bpf_trace_printk("data %s", data.argv[0]);
    return 0;
}

int syscall__probe_ret_execv(struct pt_regs* ctx) {
   //bpf_trace_printk("I am here in exit");
    struct data_t data = {};
    struct task_struct *task;
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    //bpf_trace_printk("Updating events ret value");
     events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
