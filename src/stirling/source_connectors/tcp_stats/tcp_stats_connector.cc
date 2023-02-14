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

#include "src/stirling/source_connectors/tcp_stats/tcp_stats_connector.h"

#include <string>
#include <arpa/inet.h>
#include "src/common/base/base.h"
#include "src/stirling/bpf_tools/macros.h"
#include "src/common/base/inet_utils.h"
#include "src/stirling/source_connectors/tcp_stats/print_utils.h"

BPF_SRC_STRVIEW(tcpstats_bcc_script, tcpstats);
DEFINE_string(unspec, "UNSPEC", "IP is neither IPv4 nor IPv6");
DEFINE_bool(JsonOutput, true, "Print on santdard in Json format");

namespace px {
namespace stirling {

using ProbeType = bpf_tools::BPFProbeAttachType;
const auto kProbeSpecs = MakeArray<bpf_tools::KProbeSpec>(
  {{"tcp_sendmsg", ProbeType::kEntry, "probe_entry_tcp_sendmsg", /*is_syscall*/ false},
   {"tcp_sendmsg", ProbeType::kReturn, "probe_ret_tcp_sendmsg", /*is_syscall*/ false},
   {"tcp_cleanup_rbuf", ProbeType::kEntry, "probe_entry_tcp_cleanup_rbuf", /*is_syscall*/ false}});


Status TCPStatsConnector::InitImpl() {
  sampling_freq_mgr_.set_period(kSamplingPeriod);
  push_freq_mgr_.set_period(kPushPeriod);
  PL_RETURN_IF_ERROR(InitBPFProgram(tcpstats_bcc_script));
  PL_RETURN_IF_ERROR(AttachKProbes(kProbeSpecs));
  LOG(INFO) << absl::Substitute("Number of kprobes deployed = $0", kProbeSpecs.size());
  LOG(INFO) << "Probes successfully deployed.";
  return Status::OK();
}

Status TCPStatsConnector::StopImpl() {
  Close();
  return Status::OK();
}

void AddRecHeaders(rapidjson::Document::AllocatorType& a,
                   rapidjson::Value &metricsRec ,
                   std::pair < ip_key_t, uint64_t > item,
                   std::string name) {
  std::string addr_string;
  metricsRec.AddMember("name", name, a);
  metricsRec.AddMember("event_type", json_type::tcp_stats, a);
  metricsRec.AddMember("type", "count", a);
  metricsRec.AddMember("value", uint64_t(item.second), a);
  rapidjson::Value attributes(rapidjson::kObjectType);
  int family = item.first.addr.sa.sa_family ;
  if (family == AF_INET) {
    addr_string = IPv4AddrToString(item.first.addr.in4.sin_addr).ConsumeValueOrDie();
    attributes.AddMember("remote-port",  item.first.addr.in4.sin_port, a);
  }
  else if (family == AF_INET6) {
    addr_string = IPv6AddrToString(item.first.addr.in6.sin6_addr).ConsumeValueOrDie();
    attributes.AddMember("remote-port", item.first.addr.in6.sin6_port, a);
  } else {
    addr_string = FLAGS_unspec;
  }
  attributes.AddMember("remote-ip",  std::string(addr_string), a);
  attributes.AddMember("process", std::string(item.first.name), a);
  metricsRec.AddMember("attributes", attributes.Move(), a);
  attributes.SetObject();
}

void CreateRecords(rapidjson::Document::AllocatorType& a,
                   rapidjson::Value &metricsArray,
                   std::vector < std::pair < ip_key_t, uint64_t >> items,
                   std::string name) {
  for (auto& item : items) {
    rapidjson::Value metricsRec(rapidjson::kObjectType);
    AddRecHeaders(a, metricsRec, item, name);
    metricsArray.PushBack(metricsRec.Move(), a);
    metricsRec.SetObject();
  }
}

void PrintRecordsInJson() { 
  rapidjson::Document document;
  document.SetObject();

  rapidjson::Value object(rapidjson::kObjectType);
  rapidjson::Document::AllocatorType & allocator = document.GetAllocator();

  rapidjson::Value data(rapidjson::kObjectType);
  rapidjson::Value metricsArray(rapidjson::kArrayType);

  std::vector < std::pair < ip_key_t, uint64_t >> tx_items = bcc->GetHashTable< ip_key_t, uint64_t > ("sent_bytes").get_table_offline(); 
  CreateRecords(allocator, metricsArray, tx_items, json_type::tx_metric);
  
  std::vector < std::pair < ip_key_t, uint64_t >> rx_items =
    GetHashTable < ip_key_t, uint64_t > ("recv_bytes").get_table_offline();
  CreateRecords(allocator, metricsArray, rx_items, json_type::rx_metric);

  std::vector < std::pair < ip_key_t, uint64_t >> retrans_items =
    GetHashTable < ip_key_t, uint64_t > ("sent_bytes").get_table_offline();
  CreateRecords(allocator, metricsArray, retrans_items, json_type::retrans_metric);

  data.AddMember("metrics", metricsArray.Move(), allocator);
  document.AddMember("protocol_version", "4", allocator);
  rapidjson::Value dataArray(rapidjson::kArrayType);
  dataArray.PushBack(data.Move(), allocator);
  document.AddMember("data", dataArray.Move(), allocator);

  rapidjson::StringBuffer strbuf;
  rapidjson::Writer < rapidjson::StringBuffer > writer(strbuf);
  document.Accept(writer);
  std::cout << strbuf.GetString() << std::endl;
}  

void TCPStatsConnector::TransferDataImpl(ConnectorContext * /* ctx */ ) {
  DCHECK_EQ(data_tables_.size(), 1);
  DataTable * data_table = data_tables_[0];

  if (data_table == nullptr) {
    return;
  }

  if FLAGS_Json != true {
    /* TODO: Support other output formats */
    return;
  }  
  PrintRecordsInJson();
}
}  // namespace stirling
}  // namespace px
