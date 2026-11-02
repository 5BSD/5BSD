# SPDX-License-Identifier: BSD-2-Clause
"""Incrementally read Bazel's concatenated JSON execution records."""
import json


def objects(path):
    """Yield objects, retaining text proportional to the largest pending record.

    Grow incomplete records geometrically: retrying JSON decoding after each
    fixed-size read repeatedly reparses large input-file lists. Other consumers
    must also avoid collecting every decoded record when only a subset is needed.
    """
    with path.open(encoding="utf-8") as stream:
        yield from stream_objects(stream)


def stream_objects(stream):
    """Read concatenated JSON from a caller-owned text stream without closing it."""
    decoder = json.JSONDecoder()
    buffer = ""
    eof = False
    while True:
        buffer = buffer.lstrip()
        if not buffer and eof:
            return
        try:
            value, end = decoder.raw_decode(buffer)
        except json.JSONDecodeError:
            if eof:
                raise
            chunk = stream.read(max(65536, len(buffer)))
            eof = not chunk
            buffer += chunk
            continue
        if not isinstance(value, dict):
            raise ValueError("execution log record must be a JSON object")
        yield value
        buffer = buffer[end:]
