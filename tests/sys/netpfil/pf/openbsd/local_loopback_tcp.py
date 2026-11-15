# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 The 5BSD Project
"""Verify loopback payload integrity and TCP error counters in an isolated VNET."""
import json
import re
import socket
import subprocess
import sys
import threading
import time


def counters():
    text = subprocess.check_output(["netstat", "-s", "-p", "tcp"], text=True)
    return {name: int(re.search(r"(\d+) " + phrase, text).group(1))
            for name, phrase in [("bad_checksum", "discarded for bad checksums"),
                                 ("retransmit_timeout", "retransmit timeouts")]}


family, address = {"4": (socket.AF_INET, "127.0.0.1"),
                   "6": (socket.AF_INET6, "::1")}[sys.argv[1]]
payload = bytes(range(256)) * 1024
received = bytearray()
errors = []
server = socket.socket(family)
server.settimeout(30)
server.bind((address, 0))
server.listen(1)


def consume():
    try:
        with server.accept()[0] as conn:
            conn.settimeout(30)
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                received.extend(data)
    except Exception as error:
        errors.append(repr(error))


before = counters()
start = time.monotonic()
thread = threading.Thread(target=consume, daemon=True)
thread.start()
try:
    with socket.socket(family) as client:
        client.settimeout(30)
        client.connect(server.getsockname())
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
except Exception as error:
    errors.append(repr(error))
thread.join(35)
server.close()
after = counters()
result = {"matches": received == payload, "bytes": len(received),
          "errors": errors, "thread_alive": thread.is_alive(),
          "elapsed_seconds": time.monotonic() - start,
          "counters": {key: after[key] - before[key] for key in before}}
print(json.dumps(result))
# Elapsed time is diagnostic only; correctness does not depend on host speed.
sys.exit(not (result["matches"] and not errors and not thread.is_alive()
              and all(value == 0 for value in result["counters"].values())))
