from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
import sys
import json
import time
# runs genpolicy tools on the following files
# should run this after any change to genpolicy
# usage: python3 update_policy_samples.py

with open('policy_samples.json') as f:
    samples = json.load(f)

default_yamls = samples["default"]
silently_ignored = samples["silently_ignored"]
no_policy = samples["no_policy"]
needs_containerd_pull = samples["needs_containerd_pull"]

file_base_path = "../../agent/samples/policy/yaml"

def runCmd(arg):
    return subprocess.run([arg], stdout=sys.stdout, stderr=sys.stderr, universal_newlines=True, input="", shell=True)

def timeRunCmd(arg):
    start = time.time()
    proc = runCmd(arg)
    end = time.time()

    log = f"COMMAND: {arg}\n"
    if proc.returncode != 0:
        log += f"`{arg}` failed with exit code {proc.returncode}. Stderr: {proc.stderr}, Stdout: {proc.stdout}\n"
    log += f"Time taken: {round(end - start, 2)} seconds"
    print(log)

# check we can access all files we are about to update
for file in default_yamls + silently_ignored + no_policy:
    filepath = os.path.join(file_base_path, file)
    if not os.path.exists(filepath):
        print(f"filepath does not exists: {filepath}")

# build tool
print("COMMAND: LIBC=gnu BUILD_TYPE= make")
runCmd("LIBC=gnu BUILD_TYPE= make")

# update files
genpolicy_path = "target/x86_64-unknown-linux-gnu/debug/genpolicy"

total_start = time.time()
executor = ThreadPoolExecutor(max_workers=os.cpu_count())

for file in default_yamls + no_policy + needs_containerd_pull:
    executor.submit(timeRunCmd, f"sudo {genpolicy_path} -d -y {os.path.join(file_base_path, file)}")

for file in silently_ignored:
    executor.submit(timeRunCmd, f"sudo {genpolicy_path} -d -s -y {os.path.join(file_base_path, file)}")

executor.shutdown()
total_end = time.time()

print(f"Total time taken: {total_end - total_start} seconds")
