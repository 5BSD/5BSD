# SPDX-License-Identifier: BSD-2-Clause
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

BASE = Path(__file__).resolve().parent

def module(name):
    spec = importlib.util.spec_from_file_location('cache_' + name, BASE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

profile = module('profile')
audit = module('audit')
measure = module('measure')

class ProfileTests(unittest.TestCase):
    def event(self, time, pid, program, flags, reason, path):
        return f'ELFLOAD1\t{time}\t{pid}\t1\t{program}\t{flags}\t{reason}\t4096\t1\t2\t3\t{path}\tlibtest.so\tconsumer\n'

    def test_sort_exec_reuse_and_dynamic(self):
        rows = ['ELFPROFILE_BEGIN\t1\n', self.event(20, 4, 'sh', 2, 7, '/lib/test.so'),
                self.event(10, 4, 'sh', 1, 0, '/bin/sh'),
                self.event(30, 4, 'sh', 1, 0, '/bin/sh'),
                self.event(40, 4, 'sh', 0, 1, '/lib/test.so'), 'ELFPROFILE_END\t1\n']
        result = profile.summarize(rows)
        self.assertTrue(result['complete_capture_markers'])
        self.assertFalse(result['errors'])
        row = result['libraries'][0]
        self.assertEqual(row['process_count'], 2)
        self.assertEqual(row['dynamic_loads'], 1)
        self.assertEqual(row['outcomes'], {'hit': 1, 'cache-unavailable': 1})
        self.assertEqual(row['cache_ns'], 4)

    def test_file_identity_joins_descriptor_aliases(self):
        def record(t, flags, inode, path):
            return f'ELFLOAD2\t{t}\t{t}\t1\tdaemon\t{flags}\t1\t4096\t1\t2\t3\t17\t{inode}\t{path}\tlibtest.so\tconsumer\n'
        result = profile.summarize(['ELFPROFILE_BEGIN\t2\n',
            record(1, 16, 42, r'<fd>\0'), record(2, 0, 42, r'/lib/libtest.so\0'),
            record(3, 0, 43, '/lib/libtest.so'), 'ELFPROFILE_END\t2\n'])
        self.assertFalse(result['errors'])
        self.assertEqual(len(result['libraries']), 2)
        row = next(r for r in result['libraries'] if r['file_inode'] == 42)
        self.assertEqual(row['loads'], 2)
        self.assertEqual(row['library'], '/lib/libtest.so')
        self.assertEqual(row['paths'], ['/lib/libtest.so', 'descriptor:<fd>'])

    def test_signature_failure_is_not_a_cache_miss(self):
        result = profile.summarize(['ELFPROFILE_BEGIN\t2\n',
            self.event(1, 1, 'daemon', 2 | 4, 8, '/lib/libtest.so'),
            'ELFPROFILE_END\t2\n'])
        self.assertFalse(result['errors'])
        row = result['libraries'][0]
        self.assertEqual(row['failed'], 1)
        self.assertEqual(row['outcomes'], {'source-signature-failed': 1})

    def test_incomplete_and_corrupt(self):
        result = profile.summarize(['ELFPROFILE_BEGIN\t1\n', 'ELFPROFILE_ERROR\t1\t2\n',
                                    self.event(1, 1, 'sh', 64, 0, 'bad'),
                                    self.event(2, 1, 'sh', 0, 99, 'bad')])
        self.assertFalse(result['complete_capture_markers'])
        self.assertEqual(len(result['errors']), 3)
        self.assertFalse(result['libraries'])

    def test_fd_paths_and_bad_clock(self):
        result = profile.summarize([self.event(1, 1, 'daemon', 16 | 32 | 8, 0, 'libtest.so'),
                                    self.event(2, 2, 'sh', 0, 7, '/lib/libtest.so')])
        self.assertEqual(len(result['libraries']), 2)
        row = next(r for r in result['libraries'] if r['library'].startswith('descriptor:'))
        self.assertEqual(row['incomplete_records'], 1)
        self.assertEqual(row['cache_ns'], 0)
        self.assertEqual(row['missing_exec_marker'], 1)

    def test_duplicate_and_mismatched_capture_markers(self):
        event = self.event(1, 1, 'sh', 0, 7, '/lib/libtest.so')
        for markers in (
                ['ELFPROFILE_BEGIN\t1\n', 'ELFPROFILE_BEGIN\t1\n', 'ELFPROFILE_END\t1\n'],
                ['ELFPROFILE_BEGIN\t1\n', 'ELFPROFILE_END\t1\n', 'ELFPROFILE_END\t1\n'],
                ['ELFPROFILE_BEGIN\t1\n', 'ELFPROFILE_END\t2\n']):
            with self.subTest(markers=markers):
                report = profile.summarize(markers + [event])
                self.assertFalse(report['complete_capture_markers'])
                self.assertTrue(report['errors'])
        # Independent DTrace CPU buffers may flush out of timestamp order.
        report = profile.summarize(['ELFPROFILE_END\t1\n', event,
                                    'ELFPROFILE_BEGIN\t1\n'])
        self.assertTrue(report['complete_capture_markers'])
        self.assertFalse(report['errors'])

    def test_candidate_selection_requires_clean_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture, errors = root / 'capture', root / 'stderr'
            report, selected = root / 'report.json', root / 'candidates'
            capture.write_text('ELFPROFILE_BEGIN\t1\n' +
                self.event(1, 1, 'sh', 1, 0, '/bin/sh') +
                self.event(2, 1, 'sh', 0, 7, '/lib/libtest.so') +
                'ELFPROFILE_END\t1\n')
            command = [sys.executable, '-B', str(BASE / 'profile.py'), str(capture),
                       '--output', str(report), '--library-list', str(selected)]
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('requires --collector-errors', run.stderr)
            self.assertFalse(selected.exists())
            errors.write_text('bsdinstruments: dropped 4 record(s) (buffer full)\n')
            command += ['--collector-errors', str(errors)]
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(selected.exists())
            data = json.loads(report.read_text())
            self.assertTrue(data['collector_diagnostics_checked'])
            self.assertGreater(data['collector_diagnostics_bytes'], 0)
            self.assertTrue(data['errors'])
            errors.write_text('')
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(selected.read_text(), '/lib/libtest.so\n')
            # Refusing concatenated boots must preserve previous good output.
            capture.write_text(capture.read_text() * 2)
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(selected.read_text(), '/lib/libtest.so\n')

    def test_candidate_selection_excludes_unknown_exec_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'stderr').write_text('')
            (root / 'capture').write_text('ELFPROFILE_BEGIN\t1\n' +
                self.event(2, 1, 'sh', 0, 7, '/lib/libtest.so') +
                'ELFPROFILE_END\t1\n')
            run = subprocess.run([sys.executable, '-B', str(BASE / 'profile.py'),
                str(root / 'capture'), '--output', str(root / 'report.json'),
                '--collector-errors', str(root / 'stderr'),
                '--library-list', str(root / 'candidates')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual((root / 'candidates').read_text(), '')
            report = json.loads((root / 'report.json').read_text())
            self.assertEqual(report['libraries'][0]['missing_exec_marker'], 1)

class StagedPaths(unittest.TestCase):
    def test_absolute_symlink_is_guest_relative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lib').mkdir()
            (root / 'lib/demo').write_bytes(b'ELF')
            (root / 'alias').symlink_to('/lib/demo')
            self.assertEqual(audit.inside(root, root / 'alias'), root / 'lib/demo')

    def test_escape_and_loop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'escape').symlink_to('../outside')
            (root / 'loop').symlink_to('loop')
            for name in ('escape', 'loop'):
                with self.assertRaises(ValueError):
                    audit.inside(root, root / name)

class MeasurementTests(unittest.TestCase):
    def capture(self):
        lines = []
        for number in range(4):
            for mode, duration, growth, cpu in [('ordinary', 2, 100, 1000000), ('cache', 4, 120, 3000000)]:
                lines.append(f'MEASURE mode={mode} round={number} workers=24 startup_seconds={duration} '
                             f'anonymous_object_growth_pages={growth} unique_object_growth_pages={growth} '
                             f'total_unique_object_pages=500 cache_backing_pages=10 summed_resident_pages=900 '
                             f'cache_processes={24 if mode == "cache" else 0} page_size=4096')
                lines.append(f'CPU mode={mode} round={number} workers=24 user_us={cpu} system_us=0')
        return '\n'.join(lines) + '\nELFCACHE_VM_END failures=0\n'

    def report(self, data):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'serial.log').write_text(data)
            (root / 'run.json').write_text('{"host_load_average": [30, 20, 10]}')
            return measure.summarize(root)

    def test_regression_is_not_reported_as_savings(self):
        result = self.report(self.capture())
        self.assertEqual(len(result['paired_rounds']), 3)
        self.assertEqual(result['medians']['startup_ratio_cache_over_ordinary'], 2)
        self.assertEqual(result['medians']['cpu_ratio_cache_over_ordinary'], 3)
        self.assertEqual(result['medians']['unique_growth_difference_bytes'], 20 * 4096)
        self.assertEqual(result['provenance']['host_load_average'], [30, 20, 10])
        self.assertNotIn('summed_resident_pages', str(result))

    def test_incomplete_and_duplicate_captures_rejected(self):
        capture = self.capture()
        for data in (capture.replace('ELFCACHE_VM_END failures=0', ''),
                     capture + 'CHECK FAIL authority\n',
                     capture + 'ELFCACHE_VM_END failures=1\n',
                     capture.replace('failures=0', 'failures=00'),
                     capture + capture.splitlines()[0] + '\n',
                     capture.replace('CPU mode=cache round=2', 'OMITTED mode=cache round=2')):
            with self.subTest(data=data[-100:]), self.assertRaises(ValueError):
                self.report(data)

    def test_pair_order_is_reported_from_capture(self):
        lines = self.capture().splitlines()
        # Swap complete trial blocks in measured round 1, retaining CPU rows.
        lines[4:8] = lines[6:8] + lines[4:6]
        result = self.report('\n'.join(lines) + '\n')
        self.assertEqual(result['pair_order_counts'], {'ordinary-first': 2, 'cache-first': 1})
        self.assertEqual(result['paired_rounds'][0]['order'], ['cache', 'ordinary'])
        self.assertEqual(result['medians']['startup_ratio_cache_over_ordinary'], 2)

    def test_invalid_counts_and_nonfinite_times_rejected(self):
        for old, new in [('startup_seconds=4', 'startup_seconds=nan'),
                         ('startup_seconds=4', 'startup_seconds=0'),
                         ('cache_processes=24', 'cache_processes=23'),
                         ('page_size=4096', 'page_size=4097'),
                         ('system_us=0', 'system_us=-1')]:
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.report(self.capture().replace(old, new, 1))

if __name__ == '__main__':
    unittest.main()
