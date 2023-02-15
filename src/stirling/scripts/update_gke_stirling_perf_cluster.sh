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

if [[ $(git rev-parse --abbrev-ref HEAD) != "main" ]]; then
  echo "You are not on main branch, exit ..."
  exit 1
fi

if [[ $(git status -s) != "" ]]; then
  echo "Your repository is not clean, make sure there isn't any change, exit ..."
  exit 1
fi

gke_cluster_context="gke_pl-pixies_us-west1-a_dev-cluster-stirling-perf"
if [[ $(kubectl config current-context) != "${gke_cluster_context}" ]]; then
  echo "Your kubectl context is wrong, should be ${gke_cluster_context}, exit ..."
  exit 1
fi

echo "Note down information below: "
echo "commit: $(git rev-parse HEAD)"
echo "Date & time: $(date "+%F %T")"
echo
echo

# TODO(yzhao): We
if (( $(kubectl get pods -n pl --no-headers | wc -l) < 5 )); then
  echo "Must be upgrading an existing Vizier deployment, but did not found enough pods" \
       "in the 'pl' namespace, exit ..."
  exit 1
fi

echo "You must be upgrading an existing Vizier deployment. Launching skaffold ..."
skaffold run --filename=skaffold/skaffold_vizier.yaml \
  --profile=opt \
  --label=commit="$(git rev-parse HEAD)"
