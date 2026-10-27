# SPDX-License-Identifier: BSD-2-Clause
"""Synthetic result-validation tests; these are not benchmark measurements."""
import copy
import json
import unittest
from pathlib import Path
import fio_result_check as check

JOB = '''[global]
group_reporting=0
percentile_list=50:95:99:99.9
[reader]
rw=read
[writer]
rw=randrw
fsync=1
'''


def fixture():
    lat = dict(N=20, max=1000, percentile={str(p): 100 for p in (50, 95, 99, 99.9)})
    jobs = []
    for name, active in [('reader', {'read'}), ('writer', {'read', 'write'})]:
        job = dict(jobname=name, error=0, job_runtime=60000)
        for direction in ('read', 'write', 'trim'):
            yes = direction in active
            job[direction] = dict(total_ios=20 if yes else 0,
                io_bytes=81920 if yes else 0, runtime=60000 if yes else 0,
                short_ios=0, drop_ios=0, lat_ns=copy.deepcopy(lat))
        job['sync'] = dict(total_ios=20, lat_ns=copy.deepcopy(lat))
        jobs.append(job)
    return dict(jobs=jobs)


class Results(unittest.TestCase):
    def test_valid_synthetic_result(self):
        check.validate(fixture(), check.expected_jobs(JOB), 0, 59000)

    def test_failed_or_incomplete_runs(self):
        for status in (1, -9):
            with self.assertRaises(ValueError):
                check.validate(fixture(), check.expected_jobs(JOB), status, 59000)
        changes = [lambda r: r['jobs'].pop(),
            lambda r: r['jobs'].append(copy.deepcopy(r['jobs'][0])),
            lambda r: r['jobs'][0].update(error=5),
            lambda r: r['jobs'][0].update(first_error=5),
            lambda r: r['jobs'][0]['read'].update(io_bytes=0),
            lambda r: r['jobs'][0]['read'].update(total_ios=0),
            lambda r: r['jobs'][0]['read'].update(short_ios=1),
            lambda r: r['jobs'][0]['read'].update(drop_ios=1),
            lambda r: r['jobs'][0]['write'].update(io_bytes=4096, total_ios=1),
            lambda r: r['jobs'][1]['sync'].update(total_ios=0),
            lambda r: r['jobs'][0]['read'].update(runtime=100),
            lambda r: r['jobs'][0]['read']['lat_ns'].pop('percentile'),
            lambda r: r['jobs'][0]['read']['lat_ns']['percentile'].update({'99': float('nan')})]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                result = fixture(); change(result)
                with self.assertRaises(ValueError):
                    check.validate(result, check.expected_jobs(JOB), 0, 59000)

    def test_every_requested_worker_completes(self):
        job_text = JOB.replace('[reader]', '[reader]\nnumjobs=2')
        expected = check.expected_jobs(job_text)
        result = fixture()
        result['jobs'].insert(1, copy.deepcopy(result['jobs'][0]))
        check.validate(result, expected, 0, 59000)
        for mutation in ('missing', 'extra', 'short', 'error', 'no_io'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(result)
                if mutation == 'missing': bad['jobs'].pop(1)
                elif mutation == 'extra': bad['jobs'].append(copy.deepcopy(bad['jobs'][0]))
                elif mutation == 'short': bad['jobs'][1]['read']['runtime'] = 100
                elif mutation == 'error': bad['jobs'][1]['error'] = 5
                else: bad['jobs'][1]['read']['total_ios'] = 0
                with self.assertRaises(ValueError):
                    check.validate(bad, expected, 0, 59000)

    def test_grouped_reporting_cannot_hide_workers(self):
        with self.assertRaises(ValueError):
            check.expected_jobs(JOB.replace('group_reporting=0', 'group_reporting=1'))
        with self.assertRaises(ValueError):
            check.expected_jobs(JOB.replace('[reader]', '[reader]\nnumjobs=0'))

    def test_duplicate_json_keys(self):
        with self.assertRaises(ValueError):
            json.loads('{"jobs": [], "jobs": []}', object_pairs_hook=check.unique)

    def test_maintained_job_names_are_derived(self):
        for filename in ('disk_read.fio', 'disk_state.fio'):
            jobs = check.expected_jobs(Path(__file__).with_name(filename).read_text())
            self.assertTrue(jobs)
            self.assertTrue(all(percentiles == {50, 95, 99, 99.9}
                for _, _, percentiles, _ in jobs.values()))


if __name__ == '__main__':
    unittest.main()
