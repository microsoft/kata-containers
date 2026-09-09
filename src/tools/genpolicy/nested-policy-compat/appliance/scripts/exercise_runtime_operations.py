#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import subprocess
import time
from pathlib import Path


RUNTIME_ANNOTATION = "test.katacontainers.io/runtime-operations"
TERMINATION_LOG_ANNOTATION = "test.katacontainers.io/termination-log"
FINALIZER = "test.katacontainers.io/observe-termination"
INIT_MESSAGE = "runtime-init-complete"
STOP_MESSAGE = "runtime-stop-sighup"
FALLBACK_STOP_MESSAGE = "runtime-stop-sigterm"


def kubectl(*args: str, capture: bool = True) -> str:
    result = subprocess.run(
        ["kubectl", *args],
        text=True,
        capture_output=capture,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() if capture else ""
        command = " ".join(("kubectl", *args))
        raise RuntimeError(f"{command} failed: {stderr or f'exit {result.returncode}'}")
    return result.stdout if capture else ""


def pod_json(namespace: str, name: str) -> dict:
    return json.loads(kubectl("get", "pod", name, "--namespace", namespace, "-o", "json"))


def status_by_name(pod: dict, field: str) -> dict:
    return {
        status["name"]: status
        for status in pod.get("status", {}).get(field, [])
    }


def terminated_status(pod: dict, container_name: str) -> dict | None:
    status = status_by_name(pod, "containerStatuses").get(container_name, {})
    return status.get("state", {}).get("terminated")


def wait_for_termination(namespace: str, name: str, container_name: str) -> tuple[dict, dict]:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        pod = pod_json(namespace, name)
        terminated = terminated_status(pod, container_name)
        if terminated is not None:
            return pod, terminated
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {namespace}/{name} to terminate")


def validate_runtime_fixture(pod: dict) -> tuple[str, str, str, dict]:
    metadata = pod["metadata"]
    namespace = metadata.get("namespace", "default")
    name = metadata["name"]
    generated_prefix = metadata.get("generateName", "")
    if not generated_prefix or not name.startswith(generated_prefix):
        raise RuntimeError(f"{namespace}/{name} does not match generateName prefix")

    sysctls = {
        item["name"]: str(item["value"])
        for item in pod.get("spec", {}).get("securityContext", {}).get("sysctls", [])
    }
    if sysctls.get("net.ipv4.ip_forward") != "1":
        raise RuntimeError(f"{namespace}/{name} is missing the expected sysctl")

    workload_status = status_by_name(pod, "containerStatuses").get("workload", {})
    if not workload_status.get("ready"):
        raise RuntimeError(f"{namespace}/{name} readiness probe did not succeed")

    return namespace, name, generated_prefix, sysctls


def stop_and_observe(namespace: str, name: str) -> tuple[dict, str]:
    kubectl(
        "exec",
        "--namespace",
        namespace,
        name,
        "--container",
        "workload",
        "--",
        "/bin/busybox",
        "test",
        "-f",
        "/tmp/ready",
    )
    kubectl(
        "delete",
        "pod",
        name,
        "--namespace",
        namespace,
        "--grace-period=10",
        "--wait=false",
    )

    terminated_pod, terminated = wait_for_termination(namespace, name, "workload")
    log = kubectl(
        "logs",
        "--namespace",
        namespace,
        name,
        "--container",
        "workload",
    )

    finalizers = terminated_pod.get("metadata", {}).get("finalizers", [])
    if FINALIZER not in finalizers:
        raise RuntimeError(f"{namespace}/{name} observation finalizer is missing")
    kubectl(
        "patch",
        "pod",
        name,
        "--namespace",
        namespace,
        "--type=merge",
        "-p",
        '{"metadata":{"finalizers":[]}}',
    )
    kubectl(
        "wait",
        "--namespace",
        namespace,
        "--for=delete",
        "--timeout=120s",
        f"pod/{name}",
    )
    return terminated, log


def exercise_runtime_fixture(pod: dict, custom_stop_signal: bool) -> dict:
    namespace, name, generated_prefix, sysctls = validate_runtime_fixture(pod)
    workload = next(
        container
        for container in pod.get("spec", {}).get("containers", [])
        if container.get("name") == "workload"
    )
    declared_stop_signal = workload.get("lifecycle", {}).get("stopSignal")
    if custom_stop_signal and declared_stop_signal != "SIGHUP":
        raise RuntimeError(f"{namespace}/{name} is missing the configured SIGHUP")
    if not custom_stop_signal and declared_stop_signal is not None:
        raise RuntimeError(
            f"{namespace}/{name} retains a stop signal unsupported by containerd 1.7"
        )

    terminated, log = stop_and_observe(namespace, name)
    if terminated.get("exitCode") != 0:
        raise RuntimeError(f"{namespace}/{name} did not stop gracefully")
    if STOP_MESSAGE in log:
        observed_stop_signal = "SIGHUP"
    elif FALLBACK_STOP_MESSAGE in log:
        observed_stop_signal = "SIGTERM fallback"
    elif custom_stop_signal:
        observed_stop_signal = "SIGHUP"
    elif not custom_stop_signal:
        observed_stop_signal = "containerd 1.7 default"
    if custom_stop_signal and observed_stop_signal != "SIGHUP":
        raise RuntimeError(f"{namespace}/{name} did not receive the configured SIGHUP")
    if not custom_stop_signal and observed_stop_signal == "SIGHUP":
        raise RuntimeError(f"{namespace}/{name} unexpectedly received SIGHUP")

    return {
        "exec_process": "passed",
        "generate_name": generated_prefix,
        "pod": f"{namespace}/{name}",
        "readiness_probe": "passed",
        "stop_signal": observed_stop_signal,
        "sysctls": sysctls,
        "container_log": log.strip(),
        "termination_exit_code": terminated["exitCode"],
    }


def exercise_termination_log_fixture(pod: dict) -> dict:
    gaps = []
    metadata = pod["metadata"]
    namespace = metadata.get("namespace", "default")
    name = metadata["name"]

    init_status = status_by_name(pod, "initContainerStatuses").get(
        "termination-message", {}
    )
    init_terminated = init_status.get("state", {}).get("terminated", {})
    if init_terminated.get("message") != INIT_MESSAGE:
        gaps.append("init termination message was not recorded")

    workload_status = status_by_name(pod, "containerStatuses").get("workload", {})
    if not workload_status.get("ready"):
        raise RuntimeError(f"{namespace}/{name} readiness probe did not succeed")

    terminated, log = stop_and_observe(namespace, name)
    if terminated.get("message") != STOP_MESSAGE:
        gaps.append("SIGHUP termination message was not recorded")

    return {
        "gaps": gaps,
        "init_termination_message": init_terminated.get("message", ""),
        "pod": f"{namespace}/{name}",
        "stop_signal": "SIGHUP",
        "termination_log": log.strip(),
        "termination_message": terminated.get("message", ""),
    }


def delete_pod(pod: dict) -> dict:
    metadata = pod["metadata"]
    namespace = metadata.get("namespace", "default")
    name = metadata["name"]
    kubectl(
        "delete",
        "pod",
        name,
        "--namespace",
        namespace,
        "--grace-period=10",
        "--wait=true",
        "--timeout=120s",
    )
    return {"pod": f"{namespace}/{name}", "graceful_deletion": "passed"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pods", required=True, type=Path)
    parser.add_argument("--containerd-version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    custom_stop_signal = " v1." not in args.containerd_version

    declared_pods = json.loads(args.pods.read_text(encoding="utf-8"))
    results = []
    for declared in declared_pods:
        metadata = declared["metadata"]
        namespace = metadata.get("namespace", "default")
        name = metadata["name"]
        live = pod_json(namespace, name)
        annotations = live.get("metadata", {}).get("annotations", {})
        if annotations.get(TERMINATION_LOG_ANNOTATION) == "true":
            results.append(exercise_termination_log_fixture(live))
        elif annotations.get(RUNTIME_ANNOTATION) == "true":
            results.append(exercise_runtime_fixture(live, custom_stop_signal))
        else:
            results.append(delete_pod(live))

    gaps = [
        f"{result['pod']}: {gap}"
        for result in results
        for gap in result.get("gaps", [])
    ]
    args.output.write_text(
        json.dumps(
            {"complete": not gaps, "gaps": gaps, "pods": results},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if gaps:
        raise RuntimeError("; ".join(gaps))


if __name__ == "__main__":
    main()
