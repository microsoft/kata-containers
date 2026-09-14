#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import os
import shutil
import signal
import socket
import stat
import threading
import time
from pathlib import Path


BACKEND_SUFFIX = ".npc"


class CaptureSupervisor:
    def __init__(self, roots, names, output, poll_seconds=0.01):
        self.roots = [Path(root) for root in roots]
        self.names = set(names)
        self.output = Path(output)
        self.poll_seconds = poll_seconds
        self.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.output, 0o700)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.listeners = {}
        self.intercepted_paths = set()
        self.active_connections = {}
        self.connection_number = 0
        self.errors = []
        self.write_state()

    def state(self):
        with self.lock:
            return {
                "connections": self.connection_number,
                "errors": list(self.errors),
                "intercepted_sockets": sorted(
                    str(path) for path in self.intercepted_paths
                ),
            }

    def write_state(self):
        state_path = self.output / "state.json"
        temporary = state_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(self.state(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(state_path)

    def add_error(self, message):
        with self.lock:
            self.errors.append(message)
        self.write_state()

    def candidate_paths(self):
        for root in self.roots:
            if not root.exists():
                continue
            for directory, _, files in os.walk(root):
                for name in files:
                    if name in self.names:
                        yield Path(directory) / name

    def scan_once(self):
        for path in self.candidate_paths():
            if path in self.listeners:
                continue
            try:
                mode = path.stat().st_mode
            except FileNotFoundError:
                continue
            if not stat.S_ISSOCK(mode):
                continue
            self.take_over(path, mode)

    def take_over(self, path, mode):
        backend = path.with_name(path.name + BACKEND_SUFFIX)
        if backend.exists():
            self.add_error(f"backend path already exists: {backend}")
            return

        try:
            path.rename(backend)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            os.chmod(path, stat.S_IMODE(mode))
            listener.listen(16)
            listener.settimeout(0.2)
        except OSError as error:
            if not path.exists() and backend.exists():
                backend.rename(path)
            self.add_error(f"failed to intercept {path}: {error}")
            return

        with self.lock:
            self.listeners[path] = (listener, backend)
            self.intercepted_paths.add(path)
        self.write_state()
        threading.Thread(
            target=self.accept_connections,
            args=(path, listener, backend),
            daemon=True,
        ).start()

    def accept_connections(self, path, listener, backend):
        while not self.stop_event.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return

            try:
                agent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                agent.connect(str(backend))
            except OSError as error:
                client.close()
                self.add_error(f"failed to connect relay backend {backend}: {error}")
                continue

            with self.lock:
                self.connection_number += 1
                number = self.connection_number
            self.write_state()
            worker = threading.Thread(
                target=self.capture_connection,
                args=(number, path, client, agent),
                daemon=True,
            )
            with self.lock:
                self.active_connections[number] = (client, agent, worker)
            worker.start()

    def capture_connection(self, number, path, client, agent):
        connection_dir = self.output / f"{number:06d}"
        connection_dir.mkdir(mode=0o700)
        metadata = {
            "connection": number,
            "socket": str(path),
            "started_unix_ns": time.time_ns(),
        }
        (connection_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        workers = [
            threading.Thread(
                target=self.copy_stream,
                args=(
                    client,
                    agent,
                    connection_dir / "shim-to-agent.bin",
                ),
            ),
            threading.Thread(
                target=self.copy_stream,
                args=(
                    agent,
                    client,
                    connection_dir / "agent-to-shim.bin",
                ),
            ),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        try:
            client.close()
            agent.close()
            metadata["finished_unix_ns"] = time.time_ns()
            (connection_dir / "metadata.json").write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        finally:
            with self.lock:
                self.active_connections.pop(number, None)

    def copy_stream(self, source, destination, capture_path):
        try:
            with capture_path.open("wb") as capture:
                while True:
                    data = source.recv(1024 * 1024)
                    if not data:
                        break
                    capture.write(data)
                    capture.flush()
                    destination.sendall(data)
        except OSError as error:
            self.add_error(f"relay stream failed: {error}")
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def run(self):
        while not self.stop_event.is_set():
            self.scan_once()
            self.stop_event.wait(self.poll_seconds)

    def close(self):
        self.stop_event.set()
        with self.lock:
            listeners = list(self.listeners.items())
            self.listeners.clear()
            connections = list(self.active_connections.values())
        for path, (listener, backend) in listeners:
            listener.close()
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            if backend.exists() and not path.exists():
                try:
                    backend.rename(path)
                except OSError:
                    pass
        for client, agent, _ in connections:
            for stream in (client, agent):
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        for _, _, worker in connections:
            worker.join(timeout=2)
        self.write_state()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--name", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--poll-ms", type=int, default=10)
    args = parser.parse_args()

    supervisor = CaptureSupervisor(
        roots=args.root,
        names=args.name,
        output=args.output,
        poll_seconds=args.poll_ms / 1000,
    )

    def stop(_signum, _frame):
        supervisor.close()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        supervisor.run()
    finally:
        supervisor.close()


if __name__ == "__main__":
    main()
