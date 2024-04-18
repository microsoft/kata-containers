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

ver="master"
if [[ "$#" -gt 0 ]]; then
  ver="$1"
fi

repo="https://raw.githubusercontent.com/sprt/cc-azuredisk-csi-driver/$ver/cc-deploy"
if [[ "$#" -gt 1 ]]; then
  if [[ "$2" == *"local"* ]]; then
    echo "use local deploy"
    repo="$(dirname "$(realpath "$0")")"
  fi
fi

if [ $ver != "master" ]; then
	repo="$repo/$ver"
fi

kubectl delete --ignore-not-found -f $repo/csi-azuredisk-driver.yaml
kubectl delete --ignore-not-found -f $repo/rbac-csi-azuredisk-controller.yaml
kubectl delete --ignore-not-found -f $repo/rbac-csi-azuredisk-node.yaml
kubectl delete --ignore-not-found -f $repo/csi-azuredisk-node.yaml
kubectl delete --ignore-not-found -f $repo/csi-azuredisk-controller.yaml

kubectl delete --ignore-not-found -f $repo/storageclass-cc-azuredisk-csi.yaml
kubectl delete --ignore-not-found -f $repo/storageclass-cc-azuredisk-premium-csi.yaml

echo "Driver uninstalled"
