/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#define MAX_CMD_SIZE 32
#define ARGSIZE  128

union sockaddress_t {
  struct sockaddr sa;
  struct sockaddr_in in4;
  struct sockaddr_in6 in6;
};

struct ip_key_t {
    // The process name of this process
    char name[MAX_CMD_SIZE];
    // IP address of the remote endpoint.
    union sockaddress_t addr;
};

struct latency_key_t {
    // IP address of the local endpoint
    union sockaddress_t saddr;
    // IP address of the remote endpoint.
    union sockaddress_t daddr;
};

struct sock_latency_t {
    uint64_t latency;
    uint64_t count;
};

struct socket_key_t {
    union sockaddress_t daddr;
    uint64_t slot;
};

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};


struct data_t {
    uint32_t pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    uint32_t ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    uint32_t uid;
    char comm[MAX_CMD_SIZE];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};
