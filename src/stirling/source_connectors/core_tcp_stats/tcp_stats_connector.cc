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

#include <arpa/inet.h>
#include <string>
#include <utility>

#include "src/common/base/base.h"
#include "src/common/base/inet_utils.h"
#include "src/stirling/bpf_tools/macros.h"
#include "src/stirling/source_connectors/tcp_stats/tcp_stats.h"

OBJ_STRVIEW(tcpstats_bcc_script, tcpstats);

namespace px {
namespace stirling {

// Allocating 50 MB perf buffer. It can accommodate ~125000 events
// Considering each event size ~400 bytes (struct tcp_event_t).
constexpr uint32_t kPerfBufferPerCPUSizeBytes = 50 * 1024 * 1024;

using ProbeType = bpf_tools::BPFProbeAttachType;

void HandleTcpEvent(void* cb_cookie, void* data, int /*data_size*/) {
  auto* connector = reinterpret_cast<CORETCPStatsConnector*>(cb_cookie);
  auto* event = reinterpret_cast<struct tcp_event_t*>(data);
  connector->AcceptTcpEvent(*event);
}

void CORETCPStatsConnector::AcceptTcpEvent(const struct tcp_event_t& event) {
  events_.push_back(event);
}

void HandleTcpEventLoss(void* /*cb_cookie*/, uint64_t /*lost*/) {
  // TODO(RagalahariP): Add stats counter.
}

Status CORETCPStatsConnector::InitImpl() {
  const auto perf_buffer_specs = MakeArray<bpf_tools::PerfBufferSpec>({
      {"tcp_events", HandleTcpEvent, HandleTcpEventLoss, this, kPerfBufferPerCPUSizeBytes,
       bpf_tools::PerfBufferSizeCategory::kData},
  });

  sampling_freq_mgr_.set_period(kSamplingPeriod);
  push_freq_mgr_.set_period(kPushPeriod);
  std::cout<<"I am herrreee before";
  PX_RETURN_IF_ERROR(core_->OpenCOREBPFProgram())
  std::cout<<"I am herrreee";
  return Status::OK();
}

Status CORETCPStatsConnector::StopImpl() {
  core_->Close();
  return Status::OK();
}

void CORETCPStatsConnector::TransferDataImpl(ConnectorContext* ctx) {
  DCHECK_EQ(data_tables_.size(), 1U) << "Only one table is allowed per CORETCPStatsConnector.";
}
}  // namespace stirling
}  // namespace px
