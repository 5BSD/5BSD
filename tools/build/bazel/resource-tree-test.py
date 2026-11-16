#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Kory Heard
"""Exercise descendant accounting, simultaneous memory and bounded cleanup."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time
import unittest


def workload(mode, directory):
    directory = Path(directory)
    if mode == 'linger':
        child = os.fork()
        if child:
            return
        os.setsid()
        (directory / 'linger.pid').write_text(str(os.getpid()))
        while True:
            time.sleep(1)
    if mode == 'nested':
        # Stable FreeBSD procctl ABI: P_PID = 0, PROC_REAP_ACQUIRE = 2.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.procctl(0, os.getpid(), 2, None) != 0:
            raise OSError(ctypes.get_errno(), 'PROC_REAP_ACQUIRE')
        mode = 'parallel'
    if mode == 'parallel':
        # One child is waited by its parent; the other is adopted by the
        # measurement reaper. Neither setsid nor orphaning may lose accounting.
        children = []
        for number in range(2):
            pid = os.fork()
            if pid:
                children.append(pid)
                continue
            os.setsid()
            payload = bytearray(48 * 1024 * 1024)
            for offset in range(0, len(payload), 4096):
                payload[offset] = 1
            start = time.process_time()
            while time.process_time() - start < 0.25:
                pass
            time.sleep(0.5)
            own = resource.getrusage(resource.RUSAGE_SELF)
            (directory / ('worker-%d.json' % number)).write_text(json.dumps({
                'pid': os.getpid(), 'cpu': own.ru_utime + own.ru_stime}))
            os._exit(0)
        os.waitpid(children[0], 0)
        own = resource.getrusage(resource.RUSAGE_SELF)
        (directory / 'parent.json').write_text(json.dumps({
            'cpu': own.ru_utime + own.ru_stime}))
        return
    raise ValueError(mode)


if len(sys.argv) > 1 and sys.argv[1] == '--workload':
    workload(*sys.argv[2:])
    raise SystemExit(0)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runner', type=Path, required=True)
args, remaining = parser.parse_known_args()
RUNNER = args.runner.resolve(strict=True)


class ResourceTreeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.report = self.directory / 'resources.json'

    def command(self, timeout, *command):
        return [str(RUNNER), str(self.report), str(timeout), '--', *command]

    def run_workload(self, mode, timeout=10):
        result = subprocess.run(self.command(timeout, sys.executable,
            str(Path(__file__).resolve()), '--workload', mode,
            str(self.directory)), capture_output=True, timeout=timeout + 10)
        return result, json.loads(self.report.read_text())

    def check_parallel(self, mode):
        result, report = self.run_workload(mode)
        self.assertEqual(result.returncode, 0, result.stderr)
        workers = [json.loads(p.read_text())
                   for p in self.directory.glob('worker-*.json')]
        self.assertEqual(len(workers), 2)
        cpu = report['user_seconds'] + report['system_seconds']
        expected_cpu = sum(p['cpu'] for p in workers) + json.loads(
            (self.directory / 'parent.json').read_text())['cpu']
        self.assertGreaterEqual(cpu, expected_cpu - 0.02)
        self.assertLess(cpu, expected_cpu + 0.10)
        # Require both touched allocations concurrently; max of one process
        # cannot satisfy this threshold. Interpreter baseline is additional.
        self.assertGreater(report['sampled_peak_rss_sum_bytes'], 90 * 1024**2)
        self.assertGreaterEqual(report['sampled_peak_process_count'], 2)
        self.assertGreaterEqual(report['reaped_processes'], 2)
        self.assertTrue(report['descendants_drained'])
        self.assertFalse(report['measurement_failed'])
        for worker in workers:
            with self.assertRaises(ProcessLookupError):
                os.kill(worker['pid'], 0)

    def test_parallel_waited_and_orphaned_descendants(self):
        self.check_parallel('parallel')

    def test_nested_reaper_descendants(self):
        self.check_parallel('nested')

    def test_lingering_daemon_times_out_and_is_reaped(self):
        result, report = self.run_workload('linger', timeout=1)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertTrue(report['timed_out'])
        self.assertTrue(report['descendants_drained'])
        self.assertTrue(report['root_exited'])
        pid = int((self.directory / 'linger.pid').read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_command_failure_is_preserved(self):
        result = subprocess.run(self.command(10, sys.executable, '-c',
            'raise SystemExit(23)'), capture_output=True, timeout=20)
        report = json.loads(self.report.read_text())
        self.assertEqual(result.returncode, 23)
        self.assertEqual(report['exit_status'], 23)
        self.assertFalse(report['timed_out'])

    def test_interrupt_drains_daemon(self):
        process = subprocess.Popen(self.command(10, sys.executable,
            str(Path(__file__).resolve()), '--workload', 'linger',
            str(self.directory)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not (self.directory / 'linger.pid').exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    self.fail('daemon did not start')
                time.sleep(0.02)
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 128 + signal.SIGTERM, stderr)
            report = json.loads(self.report.read_text())
            self.assertEqual(report['interrupted_signal'], signal.SIGTERM)
            self.assertTrue(report['descendants_drained'])
            pid = int((self.directory / 'linger.pid').read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)

    def test_external_daemon_is_excluded(self):
        ready = self.directory / 'external.ready'
        daemon = subprocess.Popen([sys.executable, '-c',
            'import pathlib,sys,time; payload=bytearray(96*1024*1024); '
            'pathlib.Path(sys.argv[1]).touch(); time.sleep(30)', str(ready)])
        try:
            deadline = time.monotonic() + 5
            while not ready.exists():
                if daemon.poll() is not None or time.monotonic() > deadline:
                    self.fail('external daemon did not start')
                time.sleep(0.02)
            result = subprocess.run(self.command(10, sys.executable, '-c', 'import time; time.sleep(0.3)'),
                capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(self.report.read_text())
            self.assertLess(report['sampled_peak_rss_sum_bytes'], 32 * 1024**2)
            self.assertEqual(report['sampled_peak_process_count'], 1)
            self.assertIsNone(daemon.poll())
        finally:
            daemon.terminate()
            daemon.wait(timeout=5)

    def test_existing_report_is_not_adopted(self):
        self.report.write_text('prior evidence\n')
        result = subprocess.run(self.command(10, sys.executable, '-c', 'pass'),
            capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.report.read_text(), 'prior evidence\n')


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *remaining])
