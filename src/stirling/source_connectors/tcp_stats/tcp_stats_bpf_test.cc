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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

#include <absl/strings/str_replace.h>

#include "src/common/base/base.h"
#include "src/common/exec/exec.h"
#include "src/common/testing/testing.h"
#include "src/shared/types/column_wrapper.h"
#include "src/shared/types/types.h"
#include "src/stirling/core/data_table.h"
#include "src/stirling/core/output.h"
#include "src/stirling/source_connectors/tcp_stats/tcp_stats_connector.h"
#include "src/stirling/source_connectors/tcp_stats/testing/tcp_stats_bpf_test_fixture.h"
#include "src/stirling/testing/common.h"
#include "src/stirling/utils/linux_headers.h"

namespace px {
namespace stirling {

using ::px::stirling::testing::RecordBatchSizeIs;
using ::px::stirling::testing::TcpTraceBPFTestFixture;
// using ::px::stirling::testing;

// using ::px::stirling::tcp_stats;
class TcpTraceTest : public TcpTraceBPFTestFixture {};

//-----------------------------------------------------------------------------
// Test Scenarios
//-----------------------------------------------------------------------------

TEST_F(TcpTraceTest, Capture) {
  StartTransferDataThread();
  std::string cmd = "echo \"hello\" | nc 127.0.0.1 22";
  ASSERT_OK_AND_ASSIGN(const std::string output, px::Exec(cmd));
  LOG(INFO) << output;
  StopTransferDataThread();
  std::vector<TaggedRecordBatch> tablets = ConsumeRecords(TCPStatsConnector::kTCPStatsTableNum);
  ASSERT_NOT_EMPTY_AND_GET_RECORDS(const types::ColumnWrapperRecordBatch& record_batch, tablets);
  // remote_addr:[127.0.0.1] remote_port:[22] tx:[6]

  PX_LOG_VAR(tcp_stats::PrintTCPStatsTable(record_batch));
}

}  // namespace stirling
}  // namespace px
