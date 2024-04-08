#!/bin/bash

set -euo pipefail

deploy_cc_dir="$(dirname "$(realpath "$0")")"

kubectl delete --ignore-not-found -f $deploy_cc_dir/csi-azuredisk-driver.yaml
kubectl delete --ignore-not-found -f $deploy_cc_dir/rbac-csi-azuredisk-controller.yaml
kubectl delete --ignore-not-found -f $deploy_cc_dir/rbac-csi-azuredisk-node.yaml
kubectl delete --ignore-not-found -f $deploy_cc_dir/csi-azuredisk-node.yaml
kubectl delete --ignore-not-found -f $deploy_cc_dir/csi-azuredisk-controller.yaml

kubectl delete --ignore-not-found -f $deploy_cc_dir/storageclass-cc-azuredisk-csi.yaml
kubectl delete --ignore-not-found -f $deploy_cc_dir/storageclass-cc-azuredisk-premium-csi.yaml

echo "Driver uninstalled"
