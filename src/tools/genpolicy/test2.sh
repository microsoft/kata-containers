#!/bin/bash

# k apply -f ../../agent/samples/policy/yaml/pod/
# k get pods
# k delete -f ../../agent/samples/policy/yaml/pod/

# k apply -f ../../agent/samples/policy/yaml/kubernetes/conformance/
# k get pods --all-namespaces
# k delete -f ../../agent/samples/policy/yaml/kubernetes/conformance/

# k apply -f ../../agent/samples/policy/yaml/kubernetes/conformance2/
# k get pods
# k delete -f ../../agent/samples/policy/yaml/kubernetes/conformance2/

# k apply -f ../../agent/samples/policy/yaml/configmap/ && k create -f ../../agent/samples/policy/yaml/job/
# k get pods
# k delete jobs --all && k delete -f ../../agent/samples/policy/yaml/configmap/ && k delete -f ../../agent/samples/policy/yaml/job/

# k apply -f ../../agent/samples/policy/yaml/deployment/
# k get pods
# k delete -f ../../agent/samples/policy/yaml/deployment/

# k apply -f ../../agent/samples/policy/yaml/kubernetes/fixtures/
# k get pods
# k delete jobs --all && k delete -f ../../agent/samples/policy/yaml/kubernetes/fixtures/

# k apply -f ../../agent/samples/policy/yaml/kubernetes/fixtures2/
# k get pods
# k delete -f ../../agent/samples/policy/yaml/kubernetes/fixtures2/

# k apply -f ../../agent/samples/policy/yaml/replica-set/ && k apply -f ../../agent/samples/policy/yaml/stateful-set/
# k get pods
# k delete -f ../../agent/samples/policy/yaml/replica-set/ && k delete -f ../../agent/samples/policy/yaml/stateful-set/

# k create -f ../../agent/samples/policy/yaml/webhook/
# k get pods --all-namespaces
# k delete -f ../../agent/samples/policy/yaml/webhook/

# k create -f ../../agent/samples/policy/yaml/webhook2/
# k get pods --all-namespaces
# k delete pods --all -n job-4436 && k delete pods --all -n sched-preemption-path-7666 && k delete -f ../../agent/samples/policy/yaml/webhook2/

# k delete pvc --all

set -e

export RUST_LOG=info
USE_CACHE_OPTION="-u"

UPDATE_REGO="$1"
RULES_DATA_PATH="$HOME/code/microsoft-kata-containers/src/tools/genpolicy"
GENPOLICY="${RULES_DATA_PATH}/target/debug/genpolicy"
POLICY_SAMPLES="$HOME/code/microsoft-kata-containers/src/agent/samples/policy/yaml/"
REGO_PATH="/tmp/"

declare -a yaml_files=(
    "configmap/pod-cm1.yaml"
    "configmap/pod-cm2.yaml"

    "deployment/deployment-azure-vote-back.yaml"
    "deployment/deployment-azure-vote-front.yaml"
    "deployment/deployment-busybox.yaml"

    "job/test-job.yaml"

    "kubernetes/conformance/conformance-e2e.yaml"
    "kubernetes/conformance/csi-hostpath-plugin.yaml"
    "kubernetes/conformance/csi-hostpath-testing.yaml"
    "kubernetes/conformance/etcd-statefulset.yaml"
    "kubernetes/conformance/hello-populator-deploy.yaml"
    "kubernetes/conformance/netexecrc.yaml"

    "kubernetes/conformance2/ingress-http-rc.yaml"
    "kubernetes/conformance2/ingress-http2-rc.yaml"
    "kubernetes/conformance2/ingress-multiple-certs-rc.yaml"
    "kubernetes/conformance2/ingress-nginx-rc.yaml"
    "kubernetes/conformance2/ingress-static-ip-rc.yaml"

    "kubernetes/fixtures/appsv1deployment.yaml"
    "kubernetes/fixtures/daemon.yaml"
    "kubernetes/fixtures/deploy-clientside.yaml"
    "kubernetes/fixtures/job.yaml"
    "kubernetes/fixtures/multi-resource-yaml.yaml"
    "kubernetes/fixtures/rc-lastapplied.yaml"
    "kubernetes/fixtures/rc-noexist.yaml"
    "kubernetes/fixtures/replication.yaml"

    "kubernetes/fixtures2/rc-service.yaml"
    "kubernetes/fixtures2/valid-pod.yaml"

    "kubernetes/incomplete-init/cassandra-statefulset.yaml"
    "kubernetes/incomplete-init/controller.yaml"
    "kubernetes/incomplete-init/cockroachdb-statefulset.yaml"
    "kubernetes/incomplete-init/node_ds.yaml"

    "pod/pod-exec.yaml"
    "pod/pod-one-container.yaml"
    "pod/pod-persistent-volumes.yaml"
    "pod/pod-same-containers.yaml"
    "pod/pod-spark.yaml"
    "pod/pod-three-containers.yaml"

    "replica-set/replica-busy.yaml"

    "secrets/azure-file-secrets.yaml"

    "stateful-set/web.yaml"
)
declare -a silently_ignored_yaml_files=(
    "webhook/webhook-pod1.yaml"
    "webhook/webhook-pod2.yaml"
    "webhook/webhook-pod3.yaml"
    "webhook/webhook-pod4.yaml"
    "webhook/webhook-pod5.yaml"
    "webhook/webhook-pod6.yaml"
    "webhook/webhook-pod7.yaml"

    "webhook2/webhook-pod8.yaml"
    "webhook2/webhook-pod9.yaml"
    "webhook2/webhook-pod10.yaml"
    "webhook2/webhook-pod11.yaml"
    "webhook2/webhook-pod12.yaml"
    "webhook2/webhook-pod13.yaml"
)
declare -a no_policy_yaml_files=(
    "kubernetes/fixtures/limits.yaml"
    "kubernetes/fixtures/namespace.yaml"
    "kubernetes/fixtures/quota.yaml"
)

exec_command() {
    echo "+++++++++++++++++++++++++++++++++++++++++"
    COMMAND="$1"
    echo "${COMMAND}"
    eval "${COMMAND}"
}

process_yaml() {
    YAML="${POLICY_SAMPLES}${1}"
    BASE_NAME=$(basename "${YAML}")
    REGO1="${REGO_PATH}${BASE_NAME}.rego-1"
    REGO2="${REGO_PATH}${BASE_NAME}.rego-2"
   
    exec_command "sed -i '/io.katacontainers.config.agent.policy:/d' ${YAML}"
    exec_command "${GENPOLICY} ${USE_CACHE_OPTION} -i ${RULES_DATA_PATH} -y ${YAML} -r ${2} > ${REGO2}"

    if [ "$UPDATE_REGO" = "update" ]; then
        exec_command "cp ${REGO2} ${REGO1}"
    else
        exec_command "diff ${REGO1} ${REGO2}"
    fi
}
process_yaml_no_policy() {
    YAML="${POLICY_SAMPLES}${1}"
    exec_command "${GENPOLICY} ${USE_CACHE_OPTION} -i ${RULES_DATA_PATH} -y ${YAML}"
}


exec_command "pushd ${RULES_DATA_PATH}"

for i in "${silently_ignored_yaml_files[@]}"
do
    process_yaml "${i}" "-s"
done
for i in "${yaml_files[@]}"
do
    process_yaml "${i}"
done
for i in "${no_policy_yaml_files[@]}"
do
    process_yaml_no_policy "${i}"
done

exec_command "popd"

git status | grep yaml
