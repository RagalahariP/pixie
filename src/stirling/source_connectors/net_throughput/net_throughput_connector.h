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

#include <prometheus/counter.h>

#include <memory>
#include <string>
#include <vector>

#include "src/stirling/core/output.h"
#include "src/stirling/core/types.h"
#include "src/stirling/bpf_tools/bcc_wrapper.h"
#include "src/stirling/core/source_connector.h"
#include "src/stirling/source_connectors/net_throughput/bcc_bpf_intf/net_throughput.h"
#include "src/stirling/source_connectors/net_throughput/canonical_types.h"
#include "src/stirling/utils/monitor.h"
#include "src/common/base/base.h"
#include "src/common/system/system.h"
#include "src/shared/metadata/metadata.h"
#include "src/stirling/core/canonical_types.h"
#include "src/stirling/core/source_connector.h"
#include "src/stirling/source_connectors/net_throughput/net_throughput_table.h"

namespace px {
namespace stirling {

class NetThroughputConnector : public SourceConnector, public bpf_tools::BCCWrapper {
 public:
  static constexpr std::string_view kName = "net_tx_throughput";
  static constexpr auto kSamplingPeriod = std::chrono::milliseconds{20000};
  static constexpr auto kPushPeriod = std::chrono::milliseconds{20000};
  static constexpr auto kTables = MakeArray(kNetTXStatsTable);
  static constexpr uint32_t kNetTXStatsTableNum = TableNum(kTables, kNetTXStatsTable);
  
  // clang-format off
  static constexpr DataElement kElements[] = {
      canonical_data_elements_net::kRemoteAddr,
      canonical_data_elements_net::kRemotePort,
      {"cmd", "Process command line",
       types::DataType::STRING, types::SemanticType::ST_NONE, types::PatternType::GENERAL},
      {"bytes_sent", "The number of bytes sent to the remote endpoint(s).",
         types::DataType::INT64, types::SemanticType::ST_BYTES, types::PatternType::METRIC_COUNTER},
  };

  NetThroughputConnector() = delete;
  ~NetThroughputConnector() override = default;

  static std::unique_ptr<SourceConnector> Create(std::string_view name) {
    return std::unique_ptr<SourceConnector>(new NetThroughputConnector(name));
  }

  Status InitImpl() override;
  Status StopImpl() override;
  void TransferDataImpl(ConnectorContext* ctx) override;

 protected:
  explicit NetThroughputConnector(std::string_view name)
      : SourceConnector(name, kTables), bpf_tools::BCCWrapper() {} 

};
}  // namespace stirling
}  // namespace px
