# SPDX-License-Identifier: BSD-2-Clause
"""Source-driven pkg-config generation regression tests."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("gen_pc", Path(__file__).with_name("gen-pc.py"))
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class GenerationTest(unittest.TestCase):
    def setUp(self):
        self.template = "@prefix@ @exec_prefix@ @libdir@ @sharedlibdir@ @includedir@ @VERSION@\n"
        self.header = "bzip2/libbzip2 version 9.8.7 of a release date"
        self.values = dict(prefix="/opt/base", exec_prefix="${prefix}", libdir="/opt/base/lib", sharedlibdir="/opt/base/lib", includedir="/opt/base/include")

    def test_source_version_and_paths(self):
        self.assertEqual(generator.render(self.template, self.header, self.values),
            "/opt/base ${prefix} /opt/base/lib /opt/base/lib /opt/base/include 9.8.7\n")

    def test_invalid_versions(self):
        for header in ("", self.header + "\n" + self.header, "bzip2/libbzip2 version invalid of today"):
            with self.subTest(header=header), self.assertRaises(ValueError):
                generator.render(self.template, header, self.values)

    def test_template_contract(self):
        for template in (self.template + "@UNKNOWN@", self.template.replace("@VERSION@", "")):
            with self.subTest(template=template), self.assertRaises(ValueError):
                generator.render(template, self.header, self.values)

    def test_invalid_values(self):
        for value in ("", "/usr\nInjected: true", "/usr\r", "@prefix@"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                generator.render(self.template, self.header, dict(self.values, prefix=value))


if __name__ == "__main__":
    unittest.main()
