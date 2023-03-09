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

// This file contains helper functions and variables that are required
// to export data in New Relic compatable JSON format

#pragma once

#include <utility>
#include <vector>
#include <string>
#include "src/common/json/json.h"
#include "src/stirling/source_connectors/tcp_stats/bcc_bpf_intf/tcp_stats.h"

namespace px {
namespace stirling {
namespace json_output {

static inline const std::string_view unspec = "UNSPEC";
static inline const std::string_view tx_metric = "eBPF.tcp_out_bound_throughput.metric";
static inline const std::string_view rx_metric = "eBPF.tcp_in_bound_throughput.metric";
static inline const std::string_view retrans_metric = "eBPF.tcp_retransmissions.metric";
static inline const std::string_view latency_metric = "eBPF.tcp_latency.metric";
static inline const std::string_view metrics_source = "tcp_stats";
static inline const std::string_view data_str = "data";
static inline const std::string_view metrics_str = "metrics";
static inline const std::string_view events_str = "events";
static inline const std::string_view version_str = "protocol_version";
static inline const std::string_view version_value = "4";

inline rapidjson::GenericStringRef<char> StringRef(std::string_view s) {
  return rapidjson::GenericStringRef<char>(s.data(), s.size());
}

static void AddRecHeaders(rapidjson::Document::AllocatorType& a,
                   rapidjson::Value &metricsRec ,
                   std::pair < ip_key_t, uint64_t > item,
                   const std::string_view name) {
  std::string_view addr_string;
  metricsRec.AddMember("name", json_output::StringRef(name), a);
  metricsRec.AddMember("event_type", json_output::StringRef(metrics_source), a);
  metricsRec.AddMember("type", "gauge", a);
  metricsRec.AddMember("value", item.second, a);
  rapidjson::Value attributes(rapidjson::kObjectType);

  int family = item.first.addr.sa.sa_family;
  if (family == AF_INET) {
    addr_string = IPv4AddrToString(item.first.addr.in4.sin_addr).ConsumeValueOrDie();
    attributes.AddMember("remote-port",  item.first.addr.in4.sin_port, a);
  } else if (family == AF_INET6) {
    addr_string = IPv6AddrToString(item.first.addr.in6.sin6_addr).ConsumeValueOrDie();
    attributes.AddMember("remote-port", item.first.addr.in6.sin6_port, a);
  } else {
    addr_string = unspec;
  }

  rapidjson::Value addr(rapidjson::kStringType);
  addr.SetString(addr_string.data(), addr_string.size(), a);
  attributes.AddMember("remote-ip",  addr, a);

  std::string process = item.first.name;
  rapidjson::Value pname(rapidjson::kStringType);
  pname.SetString(process.data(), process.size(), a);
  attributes.AddMember("process", pname, a);
  metricsRec.AddMember("attributes", attributes.Move(), a);
  attributes.SetObject();
}

static void AddLatencyRecHeaders(rapidjson::Document::AllocatorType& a,
                   rapidjson::Value &metricsRec ,
                   std::pair < latency_key_t, sock_latency_t > item,
                   const std::string_view name) {
  std::string_view saddr_string, daddr_string;
  metricsRec.AddMember("name", json_output::StringRef(name), a);
  metricsRec.AddMember("event_type", json_output::StringRef(metrics_source), a);
  metricsRec.AddMember("type", "gauge", a);
  metricsRec.AddMember("value", (item.second.latency / item.second.count), a);
  rapidjson::Value attributes(rapidjson::kObjectType);

  int family = item.first.saddr.sa.sa_family;
  if (family == AF_INET) {
    daddr_string = IPv4AddrToString(item.first.daddr.in4.sin_addr).ConsumeValueOrDie();
    saddr_string = IPv4AddrToString(item.first.saddr.in4.sin_addr).ConsumeValueOrDie();
    attributes.AddMember("remote-port",  item.first.daddr.in4.sin_port, a);
    attributes.AddMember("local-port",  item.first.saddr.in4.sin_port, a);
  } else if (family == AF_INET6) {
    daddr_string = IPv6AddrToString(item.first.daddr.in6.sin6_addr).ConsumeValueOrDie();
    saddr_string = IPv6AddrToString(item.first.saddr.in6.sin6_addr).ConsumeValueOrDie();
    attributes.AddMember("remote-port", item.first.daddr.in6.sin6_port, a);
    attributes.AddMember("local-port", item.first.saddr.in6.sin6_port, a);
  } else {
    saddr_string = unspec;
    daddr_string = unspec;
  }

  rapidjson::Value daddr(rapidjson::kStringType);
  rapidjson::Value saddr(rapidjson::kStringType);
  daddr.SetString(daddr_string.data(), daddr_string.size(), a);
  saddr.SetString(saddr_string.data(), saddr_string.size(), a);
  attributes.AddMember("remote-ip", daddr, a);
  attributes.AddMember("local-ip",  saddr, a);

  metricsRec.AddMember("attributes", attributes.Move(), a);
  attributes.SetObject();
}
static void CreateRecords(rapidjson::Document::AllocatorType& a,
                   rapidjson::Value &metricsArray,
                   std::vector < std::pair < ip_key_t, uint64_t >> items,
                   const std::string_view name) {
  for (auto& item : items) {
    rapidjson::Value metricsRec(rapidjson::kObjectType);
    AddRecHeaders(a, metricsRec, item, name);
    metricsArray.PushBack(metricsRec.Move(), a);
    metricsRec.SetObject();
  }
}

static void AddPerfRecHeaders(rapidjson::Document::AllocatorType& a, rapidjson::Value& eventsRec,
                              data_t item) {

 // std::cout<<"I am in AddPerfRecHeaders \n";
  eventsRec.AddMember("summary", "New process triggered", a);
  eventsRec.AddMember("category", "processStats", a);

  rapidjson::Value attributes(rapidjson::kObjectType);
  std::string process = item.comm;
  rapidjson::Value pname(rapidjson::kStringType);
  pname.SetString(process.data(), process.size(), a);
  attributes.AddMember("process", pname, a);
  attributes.AddMember("returnVal", item.retval, a);
  //if (item.type == 0) {
  //    attributes.AddMember("args",  std::string(item.argv[0]), a);
 // }
  eventsRec.AddMember("attributes", attributes.Move(), a);
  attributes.SetObject();
  #if 0
  eventsRec.AddMember("type", "gauge", a);
  eventsRec.AddMember("value", 1, a);
  rapidjson::Value attributes(rapidjson::kObjectType);

    attributes.AddMember("pid", item.pid, a);
  attributes.AddMember("returnVal", item.retval, a);
  if (item.type == 0) {
      attributes.AddMember("args", item.argv[0], a);
  }
  std::string process = item.comm;
  rapidjson::Value pname(rapidjson::kStringType);
  pname.SetString(process.data(), process.size(), a);
  attributes.AddMember("process", pname, a);
  eventsRec.AddMember("attributes", attributes.Move(), a);
  attributes.SetObject();
  #endif
}

static void CreatePerfRecords(rapidjson::Document::AllocatorType& a, rapidjson::Value& eventsArray,
                              std::vector<data_t> items) {
  //std::cout<<"I am here in CreatePerfRecords \n";
  for (auto& item : items) {
  //std::cout<<"I am here in in for loop in CreatePerfRecords \n";
    rapidjson::Value eventsRec(rapidjson::kObjectType);
    AddPerfRecHeaders(a, eventsRec, item);
    eventsArray.PushBack(eventsRec.Move(), a);
    eventsRec.SetObject();
  }
}
static void CreateLatencyRecords(rapidjson::Document::AllocatorType& a,
                   rapidjson::Value &metricsArray,
                   std::vector < std::pair < latency_key_t, sock_latency_t >> items,
                   const std::string_view name) {
  for (auto& item : items) {
    rapidjson::Value metricsRec(rapidjson::kObjectType);
    AddLatencyRecHeaders(a, metricsRec, item, name);
    metricsArray.PushBack(metricsRec.Move(), a);
    metricsRec.SetObject();
  }
}

}  // namespace json_output
}  // namespace stirling
}  // namespace px
