import concurrent.futures
import os
import subprocess
import sys
import json
import time
from pathlib import Path

# runs genpolicy tools on the following files
# should run this after any change to genpolicy
# usage: python3 update_policy_samples.py

with open('policy_samples.json') as f:
    samples = json.load(f)

default_yamls = samples["default"]
incomplete_init = samples["incomplete_init"]
silently_ignored = samples["silently_ignored"]
no_policy = samples["no_policy"]
needs_containerd_pull = samples["needs_containerd_pull"]

file_base_path = "../../agent/samples/policy/yaml"

def runCmd(arg):
    print(f"========== COMMAND: {arg}")
    try:
        return subprocess.run([arg], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, input="", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e.cmd}")
        print(f"Return code: {e.returncode}")
        print(f"Output:\n{e.output}")
        raise

def timeRunCmd(arg):
    log = [f"========== COMMAND: {arg}"]
    start = time.time()

    try:
        p = runCmd(arg)
    except subprocess.CalledProcessError as e:
        log.append(e.stdout)
        log.append(f"+++++ Failed with exit code {e.returncode}")
        raise
    else:
        if p.stdout:
            log.append(p.stdout)
    finally:
        end = time.time()
        log.append(f"Time taken: {round(end - start, 2)} seconds")
        print("\n".join(log))

# check we can access all files we are about to update
for file in default_yamls + incomplete_init + silently_ignored + no_policy:
    filepath = os.path.join(file_base_path, file)
    if not os.path.exists(filepath):
        sys.exit(f"filepath does not exists: {filepath}")

# build tool
runCmd("LIBC=gnu BUILD_TYPE= make")

# allow all users to pull container images by using containerd
runCmd("sudo chmod a+rw /var/run/containerd/containerd.sock")

print("Writing settings for testing to /tmp/genpolicy-settings.json")
runCmd("./tests/adapt_settings_for_tests.sh")

# update files
genpolicy_path = "./target/x86_64-unknown-linux-gnu/debug/genpolicy"

total_start = time.time()

with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
    futures = []

    for file in default_yamls + incomplete_init + no_policy + needs_containerd_pull:
        rego_file = "/tmp/" + Path(os.path.basename(file)).stem + "-rego.txt"
        cmd = f"{genpolicy_path} -r -d -u -j /tmp/genpolicy-settings.json -y {os.path.join(file_base_path, file)} > {rego_file}"
        futures.append(executor.submit(timeRunCmd, cmd))

    for file in silently_ignored:
        rego_file = "/tmp/" + Path(os.path.basename(file)).stem + "-rego.txt"
        cmd = f"{genpolicy_path} -r -d -u -s -j /tmp/genpolicy-settings.json -y {os.path.join(file_base_path, file)} > {rego_file}"
        futures.append(executor.submit(timeRunCmd, cmd))

    for future in concurrent.futures.as_completed(futures):
        # Surface any potential exception thrown by the future.
        future.result()

total_end = time.time()

print(f"Total time taken: {total_end - total_start} seconds")
