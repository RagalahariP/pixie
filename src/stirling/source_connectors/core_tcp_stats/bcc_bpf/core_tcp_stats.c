/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include "src/stirling/vmlinux/x86/vmlinux.h" 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "src/stirling/source_connectors/core_tcp_stats/bcc_bpf_intf/tcp_stats.h"

#ifndef BPF_TARGET_ARCH
#define BPF_TARGET_ARCH x86
#endif

/* Taken from kernel include/linux/socket.h. */
#define AF_INET         2       /* Internet IP Protocol         */
#define AF_INET6        10      /* IP version 6                 */

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
} tcp_perf_events SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10240);
        __type(key, pid_t);
        __type(value, struct sock*) ;
} sock_store SEC(".maps");

static int process_event(struct pt_regs *ctx, struct sock *sk, size_t size, int type)
{
	__u16 family;
	__u32 pid;

	struct tcp_event_t event = {};
	pid = bpf_get_current_pid_tgid() >> 32;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	event.family = family	;
	
	event.pid = pid;
        event.timestamp_ns = bpf_ktime_get_ns();
	bpf_get_current_comm(&event.name, sizeof(event.name));
  	
	event.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
  	event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);

	if (family == AF_INET) {
		bpf_probe_read_kernel(&event.saddr,
                                      sizeof(sk->__sk_common.skc_rcv_saddr),
                                      &sk->__sk_common.skc_rcv_saddr);
                bpf_probe_read_kernel(&event.daddr,
                                      sizeof(sk->__sk_common.skc_daddr),
                                      &sk->__sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		bpf_probe_read_kernel(&event.saddr,
                                      sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
                                      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                bpf_probe_read_kernel(&event.daddr,
                                      sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
                                      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
 
	event.size = size;
  	event.type = type;
	bpf_perf_event_output(ctx, &tcp_perf_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t size)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 tid = (__u32)pid_tgid;
	bpf_map_update_elem(&sock_store, &tid, &sk, BPF_ANY);
	return 0;
}

SEC("kprobe/tcp_sendpage")
int BPF_KPROBE(tcp_sendpage_entry, struct sock *sk, struct page* page, int offset,
                             size_t size)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 tid = (__u32)pid_tgid;
	bpf_map_update_elem(&sock_store, &tid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(tcp_sendmsg_exit)
{
	__u64 id = bpf_get_current_pid_tgid();
        __u32 tgid = id >> 32;
	struct sock** skp;
	skp = bpf_map_lookup_elem(&sock_store, &tgid);
	if (skp == 0) {
		return 0;
	}
	int size = PT_REGS_RC(ctx);
	struct sock* sk = *skp;
	return process_event(ctx, sk, size, kTCPTx);
}

SEC("kretprobe/tcp_sendpage")
int BPF_KRETPROBE(tcp_sendpage_exit)
{
	__u64 id = bpf_get_current_pid_tgid();
        __u32 tgid = id >> 32;
	struct sock** skp;
	skp = bpf_map_lookup_elem(&sock_store, &tgid);
	if (skp == 0) {
		return 0;
	}
	int size = PT_REGS_RC(ctx);
	struct sock* sk = *skp;
	return process_event(ctx, sk, size, kTCPTx);
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	return process_event(ctx, sk, copied, kTCPRx);
}

char LICENSE[] SEC("license") = "GPL";
