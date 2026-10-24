# SPDX-License-Identifier: BSD-2-Clause
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('resources', Path(__file__).with_name('resources.py'))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)


def budget():
    return dict(max_physical_memory_bytes=2048*1024**2, max_elapsed_seconds=2,
        min_free_memory_bytes=4096, min_free_disk_bytes=4096,
        max_used_disk_growth_bytes=1024**2, sample_interval_seconds=0.1)


def row(elapsed=0):
    return dict(elapsed_seconds=elapsed,
        memory={'hw.pagesize':4096, 'hw.physmem':2048*1024**2,
                'vm.stats.vm.v_free_count':10},
        filesystems={'/work':{'used_bytes':1024, 'available_bytes':1024**2}},
        iostat_cumulative_raw='fixture')


class Resources(unittest.TestCase):
    def test_budget_requires_explicit_finite_limits(self):
        r.budget_document(budget())
        for changes in ({'sample_interval_seconds':0}, {'max_elapsed_seconds':0},
                {'max_physical_memory_bytes':4096*1024**2},
                {'min_free_disk_bytes':True}, {'max_elapsed_seconds':float('nan')},
                {'min_free_disk_bytes':1.5}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                r.budget_document(dict(budget(), **changes))
        with self.assertRaises(ValueError): r.budget_document({})

    def test_each_budget_violation_is_fatal(self):
        start=row();self.assertEqual(r.violations(start,start,budget()),[])
        for scope,key,value in [('memory','hw.physmem',4096*1024**2),
                ('memory','vm.stats.vm.v_free_count',0),
                ('disk','available_bytes',0), ('disk','used_bytes',2*1024**2)]:
            changed=copy.deepcopy(start)
            (changed['memory'] if scope=='memory' else changed['filesystems']['/work'])[key]=value
            with self.subTest(key=key):self.assertTrue(r.violations(changed,start,budget()))
        self.assertTrue(r.violations(row(3),start,budget()))

    def test_duplicate_budget_fields(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            json.loads('{"limit":1,"limit":2}', object_pairs_hook=r.unique_object)

    def test_missing_device_measurement_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(r, 'command_output', side_effect=[
                    '4096 2048 1 2 3 4 5 6', 'device r/i w/i\nvtbd0 1 2\n']):
                with self.assertRaisesRegex(ValueError, 'omitted'):
                    r.sample([Path(temp)], ['vtbd2'], 0)

    def test_memory_input_shape(self):
        self.assertEqual(r.memory_sample('4096 2048 1 2 3 4 5 6')['hw.pagesize'],4096)
        for text in ('', '1 2', '0 2048 1 2 3 4 5 6', '4096 2048 1 -2 3 4 5 6'):
            with self.subTest(text=text),self.assertRaises(ValueError):r.memory_sample(text)

    def run_command(self, command, sampler=None):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'evidence'
            with patch.object(r,'sample', side_effect=sampler or (lambda *args:row())):
                result=r.supervise(command,output,[Path('/work')],['vtbd2'],budget())
            stored=json.loads((output/'result.json').read_text())
            self.assertEqual(stored,result)
            return result,(output/'stdout').read_text() if (output/'stdout').exists() else ''

    def test_success_and_command_failure_are_distinct(self):
        result,output=self.run_command(['/bin/sh','-c','printf retained'])
        self.assertEqual((result['result'],result['exit_status'],output),('PASS',0,'retained'))
        self.assertIn('child_max_rss_kib',result)
        result,_=self.run_command(['/bin/sh','-c','exit 7'])
        self.assertEqual((result['result'],result['exit_status']),('FAIL',7))

    def test_failed_preflight_never_starts_command(self):
        result,_=self.run_command(['/nonexistent'],lambda *args:row(3))
        self.assertEqual(result['result'],'FAIL')
        self.assertNotIn('exit_status',result)
        self.assertIn('elapsed time',result['error'])

    def test_budget_failure_terminates_running_command(self):
        calls=iter([row(),row(3)])
        result,_=self.run_command(['/bin/sleep','30'],lambda *args:next(calls))
        self.assertEqual(result['result'],'FAIL')
        self.assertEqual(result['terminated_exit_status'],-9)
        self.assertIn('child_max_rss_kib',result)

    def test_sampler_error_terminates_command_and_is_retained(self):
        calls=iter([row(),RuntimeError('measurement unavailable')])
        def sampler(*args):
            value=next(calls)
            if isinstance(value,Exception):raise value
            return value
        result,_=self.run_command(['/bin/sleep','30'],sampler)
        self.assertEqual(result['result'],'FAIL')
        self.assertEqual(result['terminated_exit_status'],-9)
        self.assertEqual(result['error'],'measurement unavailable')

    def test_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileExistsError):
                r.supervise(['/bin/true'],Path(temp),[],[],budget())


if __name__=='__main__':unittest.main()
