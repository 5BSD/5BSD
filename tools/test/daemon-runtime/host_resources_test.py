# SPDX-License-Identifier: BSD-2-Clause
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('host_resources',Path(__file__).with_name('host_resources.py'))
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)


class HostResources(unittest.TestCase):
    def test_duration_formats(self):
        for value,expected in [('0:00.21',.21),('125:03.00',7503),('2:03:04.50',7384.5),('1-02:03:04',93784)]:
            with self.subTest(value=value):self.assertEqual(h.cpu_seconds(value),expected)
        for value in ('', 'NaN', '1:70', '-1:00', '0:61:00'):
            with self.subTest(value=value),self.assertRaises(ValueError):h.cpu_seconds(value)

    def test_identity_and_units(self):
        self.assertEqual(h.parse_process('123 42 100 0:01.00',123),
            dict(pid=123,rss_bytes=43008,virtual_bytes=102400,cpu_seconds=1))
        for value in ('124 42 100 0:01', '123 -1 100 0:01', '123 42'):
            with self.subTest(value=value),self.assertRaises(ValueError):h.parse_process(value,123)

    def test_running_native_process_is_measured(self):
        result=h.sample_process(os.getpid())
        self.assertEqual(result['pid'],os.getpid())
        self.assertGreater(result['rss_bytes'],0)

    def test_violation_is_retained_before_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'samples.jsonl';m=h.HostMonitor(path,1)
            row=dict(pid=123,rss_bytes=2*1024**2,virtual_bytes=3*1024**2,cpu_seconds=1)
            with patch.object(h,'sample_process',return_value=row):
                with self.assertRaisesRegex(ValueError,'exceeds'):m.observe(123,2)
            summary=m.close();self.assertEqual(summary['samples'],1)
            self.assertEqual(json.loads(path.read_text())['rss_bytes'],2*1024**2)
            self.assertTrue(summary['budget_enforced'])
            with self.assertRaises(FileExistsError):h.HostMonitor(path,1)

    def test_exited_process_is_not_an_invented_zero_sample(self):
        with tempfile.TemporaryDirectory() as temp:
            m=h.HostMonitor(Path(temp)/'samples',0)
            with patch.object(h,'sample_process',return_value=None):self.assertFalse(m.observe(123,2))
            result=m.close();self.assertEqual(result['samples'],0);self.assertFalse(result['budget_enforced'])


if __name__=='__main__':unittest.main()
