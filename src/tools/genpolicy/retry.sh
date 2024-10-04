#!/bin/bash
kubectl delete pod busybox
target/debug/genpolicy -y ~/repos/yamls/busybox-pod.yaml
kubectl apply -f ~/repos/yamls/busybox-pod.yaml