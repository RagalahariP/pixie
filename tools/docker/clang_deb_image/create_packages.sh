#!/bin/bash
# Copyright 2018- The Pixie Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -e

CLANG_TAG="${CLANG_VERSION}-${CLANG_SUFFIX}"
CLANG_DEB_IMAGE_NAME="clang-${CLANG_TAG}.deb"
CLANG_LINTER_DEB_IMAGE_NAME="clang-linters-${CLANG_TAG}.deb"

# Create the make deb file hosting clang.
fpm -p "/image/${CLANG_DEB_IMAGE_NAME}" \
    -s dir \
    -t deb \
    -n "clang-${CLANG_VERSION}" \
    -v "${CLANG_TAG}" \
    --prefix /opt "clang-${CLANG_VERSION}" "clang-${CLANG_VERSION}-libc++"

tmpdir=$(mktemp -d)
cp -a /opt/"clang-${CLANG_VERSION}"/bin/clang-format "${tmpdir}"
cp -a /opt/"clang-${CLANG_VERSION}"/bin/clang-tidy "${tmpdir}"

pushd "${tmpdir}"

fpm -p "/image/${CLANG_LINTER_DEB_IMAGE_NAME}" \
    -s dir \
    -t deb \
    -n "clang-linters-${CLANG_VERSION}" \
    -v "${CLANG_TAG}" \
    --prefix /opt/px-dev/bin .

popd
