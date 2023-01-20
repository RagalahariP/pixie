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

namespace px {
namespace stirling {


using ProbeType = bpf_tools::BPFProbeAttachType;
const auto kProbeSpecs = MakeArray<bpf_tools::KProbeSpec>(
     {{"tcp_sendmsg", ProbeType::kEntry, "probe_entry_tcp_sendmsg", /*is_syscall*/ false},
     {"tcp_sendmsg", ProbeType::kReturn, "probe_ret_tcp_sendmsg", /*is_syscall*/ false}});

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

template <typename TBPFTableKey, typename TBPFTableVal>
std::string BPFMapInfo(bpf_tools::BCCWrapper* bcc, std::string_view name) {
  auto map = bcc->GetHashTable<TBPFTableKey, TBPFTableVal>(name.data());
  size_t map_size = map.get_table_offline().size();
  if (1.0 * map_size / map.capacity() > 0.9) {
    LOG(WARNING) << absl::Substitute("BPF Table $0 is nearly at capacity [size=$0 capacity=$1]",
                                     map_size, map.capacity());
  }
  return absl::Substitute("\nBPFTable=$0 occupancy=$1 capacity=$2", name, map_size, map.capacity());
}

namespace internal {
inline rapidjson::GenericStringRef<char> StringRef(std::string_view s) {
  return rapidjson::GenericStringRef<char>(s.data(), s.size());
}
}
void NetThroughputConnector::TransferDataImpl(ConnectorContext* /* ctx */) {
  DCHECK_EQ(data_tables_.size(), 1);
  DataTable* data_table = data_tables_[0];

  if (data_table == nullptr) {
    return;
}

  std::vector<std::pair<ip_key_t, uint64_t>> items =
      GetHashTable<ip_key_t, uint64_t>("ipv4_send_bytes").get_table_offline();

  rapidjson::Document document;
  document.SetObject();

  rapidjson::Value object(rapidjson::kObjectType);
  rapidjson::Document::AllocatorType& allocator = document.GetAllocator();

  // Create metrics list from table information
  // For example:
  // 		"metrics": [{
  //			"attributes": {
  //				"eBPF.exitedPname": "docker-init"
  //			},
  //			"value": 1,
  //			"name": "eBPF.numberOfProcessExited.metric",
  //			"event_type": "processStatus",
  //			"type": "count"
  //		}]


  rapidjson::Value data(rapidjson::kObjectType);
  rapidjson::Value metricsArray(rapidjson::kArrayType);
  for (auto& item : items) {
      //char buf[INET_ADDRSTRLEN];
      //std::cout<<"Family is item.first.addr.sa.sa_family " << item.first.addr.sa.sa_family << std::endl ;
      if (item.first.addr.sa.sa_family == AF_INET) {
          //if (inet_ntop(AF_INET, &(item.first.addr.in4.sin_addr), buf, INET_ADDRSTRLEN) != nullptr) {
             //std::cout<<item.second << " bytes" <<" are transmitted to " << buf << " by the process - " << item.first.name << std::endl << std::endl ;
             //char buf1[INET_ADDRSTRLEN];
             //buf1 = IPv4SockAddrToString(item.first.addr.in4);
             //std::cout<<"IPv4SockAddrToString " << IPv4AddrToString(item.first.addr.in4.sin_addr) ;   
             rapidjson::Value metricsRec(rapidjson::kObjectType);
             rapidjson::Value attributes(rapidjson::kObjectType);
             metricsRec.AddMember("name", "eBPF.tcp_egress_throughput.metric", allocator);
             metricsRec.AddMember("event_type", "egressTCPThroughput", allocator);
             metricsRec.AddMember("type", "count", allocator);
             metricsRec.AddMember("value", uint64_t(item.second), allocator);
             //metricsRec.AddMember("value", 5, allocator);
             //attributes.AddMember("remote-ip",  internal::StringRef(buf), allocator);
             std::string addr_string = IPv4AddrToString(item.first.addr.in4.sin_addr).ConsumeValueOrDie() ; 
             std::cout << "addr_string is "<< addr_string << " and length is " << addr_string.length() << std::endl ;
             attributes.AddMember("remote-ip",  std::string(addr_string), allocator);
             attributes.AddMember("process", internal::StringRef(item.first.name), allocator);
             metricsRec.AddMember("attributes", attributes, allocator);
             metricsArray.PushBack(metricsRec, allocator);
             addr_string = "";
  }
  else {
     std::cout<< "IPv6 address" << std::endl;
     continue ;
  }
  }
  data.AddMember("metrics", metricsArray, allocator);
  document.AddMember("protocol_version", "4", allocator);
  rapidjson::Value dataArray(rapidjson::kArrayType);
  dataArray.PushBack(data, allocator);
  document.AddMember("data", dataArray, allocator);

   rapidjson::StringBuffer strbuf;
   rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
   document.Accept(writer);
   std::cout<<strbuf.GetString()<<std::endl;
      
      // TODO: family is coming as 0 
        /* char *addr;
      if (inet_ntop(AF_INET, &(item.first.addr.in4.sin_addr), *addr, INET_ADDRSTRLEN) != nullptr) {
          //std::cout<<item.second << " bytes" <<" are transmitted to " << buf << " by the process - " << item.first.name << std::endl << std::endl ;
          //auto addr = buf ; 
          addr.erase(addr.find('\0'));
          rapidjson::Value metricsRec(rapidjson::kObjectType);
          rapidjson::Value attributes(rapidjson::kObjectType);
          metricsRec.AddMember("name", "eBPF.tcp_tx.metric", allocator);
          metricsRec.AddMember("event_type", "egressTCPThroughput", allocator);
          metricsRec.AddMember("type", "count", allocator);
          metricsRec.AddMember("value", uint64_t(item.second), allocator);
          //metricsRec.AddMember("value", 5, allocator);
          attributes.AddMember("remote-ip",  internal::StringRef(*addr), allocator);
          attributes.AddMember("process", internal::StringRef(item.first.name), allocator);
          metricsRec.AddMember("attributes", attributes, allocator);
          metricsArray.PushBack(metricsRec, allocator);      
      }
  }
  data.AddMember("metrics", metricsArray, allocator);
  document.AddMember("protocol_version", "4", allocator);
  rapidjson::Value dataArray(rapidjson::kArrayType);
  dataArray.PushBack(data, allocator);
  document.AddMember("data", dataArray, allocator);

   rapidjson::StringBuffer strbuf;
   rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
   document.Accept(writer);
   std::cout<<strbuf.GetString()<<std::endl;*/
  # if 0
  std::vector<std::pair<ipv4_key_t, pidruntime_val_t>> items =
      GetHashTable<uint16_t, pidruntime_val_t>("pid_cpu_time").get_table_offline();
 int64_t timestamp = AdjustedSteadyClockNowNS();
 std::cout<<"TransferDataImpl - Debug  << timestamp "<< timestamp <<"\n" ;


    DataTable::RecordBuilder<&kTable> r(data_table, time);
    r.Append<r.ColIndex("remote_addr")>(it.remote_endpoint().AddrStr());
    r.Append<r.ColIndex("pid")>(item.first);
    r.Append<r.ColIndex("runtime_ns")>(item.second.run_time - prev_run_time);
    r.Append<r.ColIndex("cmd")>(item.second.name);

    prev_run_time_map_[item.first] = item.second.run_time;
  #endif 
}

}  // namespace stirling
}  // namespace px
