# SPDX-License-Identifier: BSD-2-Clause
"""Run an owned SSH operation and journal failed attempts as well as successes."""
import hashlib
from pathlib import Path
import subprocess
import time


def invoke(argv, *, label, command, output, env, deadline, tick, publish,
           input_path=None, max_bytes=32 * 1024**2):
    output = Path(output)
    child = None
    created = False
    failure = None
    begin = time.monotonic()
    try:
        with (Path(input_path) if input_path is not None else Path('/dev/null')).open('rb') as stream, output.open('xb') as log:
            created = True
            child = subprocess.Popen(argv, stdin=stream, stdout=log,
                stderr=subprocess.STDOUT, env=env, start_new_session=True)
            while child.poll() is None:
                tick()
                if time.monotonic() > deadline:
                    raise TimeoutError('explicit root-operation phase deadline')
                if output.stat().st_size > max_bytes:
                    raise ValueError('root-operation output exceeds evidence budget')
                time.sleep(0.2)
            if output.stat().st_size > max_bytes:
                raise ValueError('root-operation output exceeds evidence budget')
    except BaseException as error:
        failure = repr(error)
        raise
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        record = dict(label=label, command=command,
            status=child.returncode if child is not None else None,
            pid=child.pid if child is not None else None,
            seconds=time.monotonic() - begin, output_created=created,
            output_sha256=None)
        if created:
            with output.open('rb') as stream:
                record['output_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        if failure is not None:
            record['error'] = failure
        publish(record)
    return record
