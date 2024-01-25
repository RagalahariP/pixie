/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __CORE_TCPSTATS_H
#define __CORE_TCPSTATS_H

#define TASK_COMM_LEN   16

enum tcp_event_type_t {
  // Unknown Event.
  kUnknownEvent,

  // TCP egress data event.
  kTCPTx,

  // TCP ingress data event.
  kTCPRx,

  // TCP retransmissions.
  kTCPRetransmissions,
};

struct tcp_event_t {
  // The time when this was captured in the BPF time.
  __u64 timestamp_ns;

  // The unique identifier of the process.
  pid_t pid;
  
  // The family of the TCP event.
  __u16 family;

  // The source address of the TCP event.
  unsigned __int128 saddr;
  
  // The destination address of the TCP event.
  unsigned __int128 daddr;
  
  // The local port of the TCP event.
  __u16 lport;
  
  // The destination port of the TCP event.
  __u16 dport;

  // The outcome of the TCP event.
  __u64 size;
  
  // The process name.
  char name[TASK_COMM_LEN];
  
  // Source of event.
  enum tcp_event_type_t type;
};

#endif /* __CORE_TCPSTATS_H */ 
