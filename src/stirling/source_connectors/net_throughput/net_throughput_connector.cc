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

#include "src/stirling/source_connectors/net_throughput/net_throughput_connector.h"

#include <string>
#include <arpa/inet.h>
#include "src/common/base/base.h"
#include "src/stirling/bpf_tools/macros.h"
#include "src/common/base/inet_utils.h"

BPF_SRC_STRVIEW(netthroughput_bcc_script, netthroughput);
DEFINE_string(unspec, "UNSPEC", "IP is neither IPv4 nor IPv6");

namespace px {
namespace stirling {


using ProbeType = bpf_tools::BPFProbeAttachType;
const auto kProbeSpecs = MakeArray<bpf_tools::KProbeSpec>(
     {{"tcp_sendmsg", ProbeType::kEntry, "probe_entry_tcp_sendmsg", /*is_syscall*/ false},
     {"tcp_sendmsg", ProbeType::kReturn, "probe_ret_tcp_sendmsg", /*is_syscall*/ false},
     {"tcp_cleanup_rbuf", ProbeType::kEntry, "probe_entry_tcp_cleanup_rbuf", /*is_syscall*/ false}});

Status NetThroughputConnector::InitImpl() {
  sampling_freq_mgr_.set_period(kSamplingPeriod);
  push_freq_mgr_.set_period(kPushPeriod);
  PL_RETURN_IF_ERROR(InitBPFProgram(netthroughput_bcc_script));
  PL_RETURN_IF_ERROR(AttachKProbes(kProbeSpecs));
  LOG(INFO) << absl::Substitute("Number of kprobes deployed = $0", kProbeSpecs.size());
  LOG(INFO) << "Probes successfully deployed.";
  return Status::OK();
}

Status NetThroughputConnector::StopImpl() {
  Close();
  return Status::OK();
}

# if 0
namespace internal {
inline rapidjson::GenericStringRef<char> StringRef(std::string_view s) {
  return rapidjson::GenericStringRef<char>(s.data(), s.size());
}
}
#endif

void  AddRecHeaders(rapidjson::Value &metricsRec, rapidjson::Document::AllocatorType& a,
                    std::pair<ip_key_t, uint64_t> item, int family) {
      std::string addr_string;
      metricsRec.AddMember("name", "eBPF.tcp_out_bound_throughput.metric", a);
      metricsRec.AddMember("event_type", "egressTCPThroughput", a);
      metricsRec.AddMember("type", "count", a);
      metricsRec.AddMember("value", uint64_t(item.second), a);
      rapidjson::Value attributes(rapidjson::kObjectType);
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


void NetThroughputConnector::TransferDataImpl(ConnectorContext * /* ctx */ ) {
  DCHECK_EQ(data_tables_.size(), 1);
  DataTable * data_table = data_tables_[0];

  if (data_table == nullptr) {
    return;
  }

  std::vector < std::pair < ip_key_t, uint64_t >> items =
    GetHashTable < ip_key_t, uint64_t > ("ipv4_send_bytes").get_table_offline();

  rapidjson::Document document;
  document.SetObject();

  rapidjson::Value object(rapidjson::kObjectType);
  rapidjson::Document::AllocatorType & allocator = document.GetAllocator();

  rapidjson::Value data(rapidjson::kObjectType);
  rapidjson::Value metricsArray(rapidjson::kArrayType);

  for (auto& item : items) {
      rapidjson::Value metricsRec(rapidjson::kObjectType);
      AddRecHeaders(metricsRec, allocator, item, item.first.addr.sa.sa_family);
      metricsArray.PushBack(metricsRec.Move(), allocator);
      metricsRec.SetObject();
  }

  data.AddMember("metrics", metricsArray.Move(), allocator);
  document.AddMember("protocol_version", "4", allocator);
  rapidjson::Value dataArray(rapidjson::kArrayType);
  dataArray.PushBack(data.Move(), allocator);
  document.AddMember("data", dataArray.Move(), allocator);

  rapidjson::StringBuffer strbuf;
  rapidjson::Writer < rapidjson::StringBuffer > writer(strbuf);
  document.Accept(writer);
  std::cout << strbuf.GetString() << std::endl;
  fflush(stdout);
}
}  // namespace stirling
}  // namespace px
