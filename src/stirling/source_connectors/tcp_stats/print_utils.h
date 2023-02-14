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
namespace px {
namespace stirling {
  namespace json_type {
    const std::string unspec = "UNSPEC";
    const std::string tx_metric = "eBPF.tcp_out_bound_throughput.metric";
    const std::string rx_metric = "eBPF.tcp_in_bound_throughput.metric";
    const std::string retrans_metric = "eBPF.tcp_retransmissions.metric";
    const std::string tcp_stats = "tcp_stats";
    # if 0
    DEFINE_string(unspec, "UNSPEC", "IP is neither IPv4 nor IPv6");
    DEFINE_string(tx_metric, "eBPF.tcp_out_bound_throughput.metric", "TCP TX metric name");
    DEFINE_string(rx_metric, "eBPF.tcp_in_bound_throughput.metric", "TCP RX metric name");
    DEFINE_string(retrans_metric, "eBPF.tcp_retransmissions.metric", "TCP retrans metric name");
    DEFINE_string(tcp_stats, "tcp_stats", "TCP metrics");
    #endif
  }
}
}
