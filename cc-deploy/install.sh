#!/bin/bash

set -euo pipefail

deploy_cc_dir="$(dirname "$(realpath "$0")")"

kubectl apply -f $deploy_cc_dir/csi-azuredisk-driver.yaml
kubectl apply -f $deploy_cc_dir/rbac-csi-azuredisk-controller.yaml
kubectl apply -f $deploy_cc_dir/rbac-csi-azuredisk-node.yaml
kubectl apply -f $deploy_cc_dir/csi-azuredisk-node.yaml
kubectl apply -f $deploy_cc_dir/csi-azuredisk-controller.yaml

kubectl apply -f $deploy_cc_dir/storageclass-cc-azuredisk-csi.yaml
kubectl apply -f $deploy_cc_dir/storageclass-cc-azuredisk-premium-csi.yaml

echo "Driver installed"
