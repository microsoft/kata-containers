#!/bin/bash

# Copyright 2020 The Kubernetes Authors.
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

set -euo pipefail

if [[ "$#" -gt 0 ]] && [[ "$1" = "local" ]]; then
  repo="$(dirname "$(realpath "$0")")"
else
  repo="https://raw.githubusercontent.com/microsoft/kata-containers/cc-azuredisk-csi-driver/latest/cc-deploy/latest"
fi

kubectl apply -f $repo/csi-azuredisk-driver.yaml
kubectl apply -f $repo/rbac-csi-azuredisk-controller.yaml
kubectl apply -f $repo/rbac-csi-azuredisk-node.yaml
kubectl apply -f $repo/csi-azuredisk-node.yaml
kubectl apply -f $repo/csi-azuredisk-controller.yaml

kubectl apply -f $repo/storageclass-cc-azuredisk-csi.yaml
kubectl apply -f $repo/storageclass-cc-azuredisk-csi-premium.yaml

echo "Driver installed"
