# SPDX-License-Identifier: BSD-2-Clause
"""Validate fio workload completion, not performance acceptance or provenance."""
import argparse
import configparser
import hashlib
import json
import math
from pathlib import Path


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError('invalid or missing nonnegative counter')
    return value


def expected_jobs(text):
    config = configparser.ConfigParser(interpolation=None, allow_no_value=True)
    config.read_string(text)
    if 'global' not in config:
        raise ValueError('job file requires global options')
    result = {}
    modes = {'read': {'read'}, 'randread': {'read'},
             'write': {'write'}, 'randwrite': {'write'},
             'randrw': {'read', 'write'}}
    for name in config.sections():
        if name == 'global':
            continue
        options = dict(config['global']); options.update(config[name])
        if options.get('rw') not in modes:
            raise ValueError('unsupported workload direction')
        if options.get('group_reporting') != '0':
            raise ValueError('requires per-worker reporting')
        workers = int(options.get('numjobs', '1'))
        if workers < 1:
            raise ValueError('invalid worker count')
        percentiles = {float(x) for x in options['percentile_list'].split(':')}
        if not percentiles or any(not math.isfinite(x) or not 0 < x <= 100 for x in percentiles):
            raise ValueError('invalid requested percentiles')
        result[name] = (modes[options['rw']], int(options.get('fsync', '0')) > 0, percentiles, workers)
    if not result:
        raise ValueError('no expected jobs')
    return result


def latency(section, required):
    stats = section.get('lat_ns', {})
    integer(stats.get('N'), 1)
    integer(stats.get('max'), 1)
    values = stats.get('percentile')
    if not isinstance(values, dict):
        raise ValueError('missing latency percentiles')
    parsed = {}
    for key, value in values.items():
        percentile = float(key)
        if not math.isfinite(percentile) or percentile in parsed:
            raise ValueError('invalid or duplicate percentile')
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('invalid latency value')
        parsed[percentile] = value
    if not required <= parsed.keys():
        raise ValueError('required latency percentiles missing')


def validate(report, expected, exit_status, minimum_runtime_ms):
    if type(exit_status) is not int or exit_status != 0:
        raise ValueError('fio process did not succeed')
    integer(minimum_runtime_ms, 1)
    if not isinstance(report, dict) or not isinstance(report.get('jobs'), list):
        raise ValueError('missing fio jobs')
    jobs = {}
    for job in report['jobs']:
        if not isinstance(job, dict) or not isinstance(job.get('jobname'), str):
            raise ValueError('invalid fio job')
        jobs.setdefault(job['jobname'], []).append(job)
    if jobs.keys() != expected.keys():
        raise ValueError('job results differ from requested matrix')
    for name, (directions, sync, percentiles, workers) in expected.items():
        if len(jobs[name]) != workers:
            raise ValueError(name + ': worker results differ from requested count')
        for job in jobs[name]:
            validate_worker(job, name, directions, sync, percentiles, minimum_runtime_ms)


def validate_worker(job, name, directions, sync, percentiles, minimum_runtime_ms):
    if integer(job.get('error')) != 0 or job.get('first_error', 0) != 0:
        raise ValueError(name + ': reported I/O error')
    integer(job.get('job_runtime'), minimum_runtime_ms)
    for direction in ('read', 'write', 'trim'):
        section = job.get(direction)
        if not isinstance(section, dict):
            raise ValueError(name + ': missing direction counters')
        count = integer(section.get('total_ios'))
        size = integer(section.get('io_bytes'))
        if integer(section.get('short_ios')) or integer(section.get('drop_ios')):
            raise ValueError(name + ': short or dropped I/O')
        if direction in directions:
            if count == 0 or size == 0:
                raise ValueError(name + ': no completed ' + direction + ' I/O')
            integer(section.get('runtime'), minimum_runtime_ms)
            latency(section, percentiles)
        elif count or size:
            raise ValueError(name + ': unexpected ' + direction + ' I/O')
    if sync:
        section = job.get('sync', {})
        integer(section.get('total_ios'), 1)
        latency(section, percentiles)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job-file', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--fio-exit-status', type=int, required=True)
    parser.add_argument('--minimum-runtime-ms', type=int, required=True)
    args = parser.parse_args()
    job_bytes, result_bytes = args.job_file.read_bytes(), args.result.read_bytes()
    report = json.loads(result_bytes, object_pairs_hook=unique)
    validate(report, expected_jobs(job_bytes.decode()), args.fio_exit_status,
             args.minimum_runtime_ms)
    print(json.dumps(dict(scope='fio-workload-completion-check', result='PASS',
        performance_qualified=False, provenance_verified=False,
        job_sha256=hashlib.sha256(job_bytes).hexdigest(),
        result_sha256=hashlib.sha256(result_bytes).hexdigest(),
        supplied_exit_status=args.fio_exit_status,
        minimum_runtime_ms=args.minimum_runtime_ms), sort_keys=True))


if __name__ == '__main__':
    main()
