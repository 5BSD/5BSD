#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Typed source setting serialization, without accepting native flag injection."""
import unittest
from source_graph import setting_arguments


class SettingsTest(unittest.TestCase):
    def test_scalars(self):
        self.assertEqual(setting_arguments({"//cfg:enabled": True, "//cfg:jobs": 16, "//cfg:name": "two words"}),
            ["--//cfg:enabled=true", "--//cfg:jobs=16", "--//cfg:name=two words"])

    def test_false_and_empty(self):
        self.assertEqual(setting_arguments({}), [])
        self.assertEqual(setting_arguments({"//:flag": False}), ["--//:flag=false"])

    def test_invalid_labels(self):
        for key in ("--spawn_strategy", "//cfg:flag=value", "//cfg:flag\n", "@external//cfg:flag", 1):
            with self.subTest(key=key), self.assertRaises(ValueError):
                setting_arguments({key: True})

    def test_invalid_values(self):
        for value in (None, 1.5, [], {}, "newline\n", "nul\0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                setting_arguments({"//cfg:flag": value})

    def test_invalid_container(self):
        for value in ([], None, "--flag"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                setting_arguments(value)


if __name__ == "__main__":
    unittest.main()
