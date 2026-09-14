#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "hvsock_capture.py"
SPEC = importlib.util.spec_from_file_location("hvsock_capture", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CaptureSupervisorTest(unittest.TestCase):
    def test_relays_and_captures_both_directions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            socket_path = root / "ch-vm.sock"
            output = root / "capture"
            backend = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            backend.bind(str(socket_path))
            backend.listen(1)

            def serve():
                connection, _ = backend.accept()
                data = connection.recv(4096)
                connection.sendall(b"OK\n" + data)
                connection.close()

            server = threading.Thread(target=serve)
            server.start()

            supervisor = MODULE.CaptureSupervisor(
                roots=[root],
                names=["ch-vm.sock"],
                output=output,
            )
            supervisor.scan_once()

            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(socket_path))
            client.sendall(b"CONNECT 1024\nrequest")
            client.shutdown(socket.SHUT_WR)
            response = client.recv(4096)
            client.close()

            server.join(timeout=2)
            for _ in range(100):
                capture = output / "000001" / "agent-to-shim.bin"
                if capture.exists() and capture.read_bytes():
                    break
                time.sleep(0.01)
            supervisor.close()
            backend.close()

            self.assertEqual(response, b"OK\nCONNECT 1024\nrequest")
            self.assertEqual(
                (output / "000001" / "shim-to-agent.bin").read_bytes(),
                b"CONNECT 1024\nrequest",
            )
            self.assertEqual(
                (output / "000001" / "agent-to-shim.bin").read_bytes(),
                response,
            )
            self.assertEqual(
                supervisor.state()["intercepted_sockets"],
                [str(socket_path)],
            )

if __name__ == "__main__":
    unittest.main()
