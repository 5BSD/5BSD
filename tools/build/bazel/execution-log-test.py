#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Regression checks for execution-log record boundaries and malformed input."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from execution_log import objects, stream_objects


class ExecutionLogTests(unittest.TestCase):
    def decode(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution.json"
            path.write_text(text, encoding="utf-8")
            return list(objects(path))

    def test_large_records_and_unicode(self):
        records = [{"text": "é" * 300000}, {"args": ["\\", '"', "\n"]}, {}]
        self.assertEqual(self.decode(" \n" + "\n\t".join(
            json.dumps(row, ensure_ascii=False) for row in records) + "\n"), records)

    def test_empty_and_whitespace(self):
        self.assertEqual(self.decode(""), [])
        self.assertEqual(self.decode(" \t\n" * 70000), [])

    def test_truncation_and_invalid_tail(self):
        for data in ['{"a":', '{} {"a":', '{} invalid', '{"a":"unterminated']:
            with self.subTest(data=data), self.assertRaises(json.JSONDecodeError):
                self.decode(data)

    def test_caller_owned_stream(self):
        stream = io.StringIO('{"a": 1}\n{"b": [2, 3]}')
        self.assertEqual(list(stream_objects(stream)), [{"a": 1}, {"b": [2, 3]}])
        self.assertFalse(stream.closed)

    def test_stream_rejects_truncated_tail(self):
        stream = io.StringIO('{"ok": true}{"bad":')
        iterator = stream_objects(stream)
        self.assertEqual(next(iterator), {"ok": True})
        with self.assertRaises(json.JSONDecodeError):
            next(iterator)
        self.assertFalse(stream.closed)

    def test_nonobject_records(self):
        for data in ['[]', '1', 'null', '"text"']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.decode(data)


if __name__ == "__main__":
    unittest.main()
