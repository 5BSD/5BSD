# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 The 5BSD Project
"""Verify odd/even UDP payloads and checksum counters in an isolated VNET."""
import json
import re
import socket
import subprocess
import sys
import time


def counters():
    text = subprocess.check_output(["netstat", "-s", "-p", "udp"], text=True)
    phrases = {"bad_checksum": "with bad checksum",
               "no_checksum": "with no checksum",
               "bad_length": "with bad data length field",
               "full_socket": "dropped due to full socket buffers"}
    return {name: int(re.search(r"(\d+) " + phrase, text).group(1))
            for name, phrase in phrases.items()}


family, address = {"4": (socket.AF_INET, "127.0.0.1"),
                   "6": (socket.AF_INET6, "::1")}[sys.argv[1]]
lengths = (1, 2, 7, 512, 1472, 1473, 8191, 8192)
completed = []
errors = []
before = counters()
start = time.monotonic()
try:
    with socket.socket(family, socket.SOCK_DGRAM) as server, \
            socket.socket(family, socket.SOCK_DGRAM) as client:
        server.settimeout(30)
        client.settimeout(30)
        server.bind((address, 0))
        client.connect(server.getsockname())
        for length in lengths:
            payload = (bytes(range(256)) * 32)[:length]
            if client.send(payload) != length:
                raise RuntimeError("short request send")
            data, peer = server.recvfrom(65535)
            if data != payload:
                raise RuntimeError("request payload mismatch")
            if server.sendto(data, peer) != length:
                raise RuntimeError("short reply send")
            if client.recv(65535) != payload:
                raise RuntimeError("reply payload mismatch")
            completed.append(length)
except Exception as error:
    errors.append(repr(error))
after = counters()
result = {"matches": completed == list(lengths), "payload_lengths": completed,
          "errors": errors, "elapsed_seconds": time.monotonic() - start,
          "counters": {key: after[key] - before[key] for key in before}}
print(json.dumps(result))
# Timing is diagnostic; no performance threshold is used.
sys.exit(not (result["matches"] and not errors
              and all(value == 0 for value in result["counters"].values())))
