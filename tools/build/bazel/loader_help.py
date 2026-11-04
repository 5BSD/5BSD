# SPDX-License-Identifier: BSD-2-Clause
"""Stream the ordered Make help inputs into the maintained AWK algorithm."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys


def merge(awk, script, sources, output, runtime):
    if not sources:
        raise ValueError('ordered help sources required')
    sources = [path.resolve(strict=True) for path in sources]
    script = script.resolve(strict=True)
    awk = awk.resolve(strict=True)
    output = output.absolute()
    if output.resolve() in [*sources, script, awk]:
        raise ValueError('help output must not overwrite an input')
    environment = {'LC_ALL': 'C'}
    if runtime:
        environment['LD_LIBRARY_PATH'] = ':'.join(sorted({str(p.resolve(strict=True).parent) for p in runtime}))
    try:
        with output.open('wb') as stream:
            process = subprocess.Popen([str(awk), '-f', str(script)],
                stdin=subprocess.PIPE, stdout=stream, env=environment)
            try:
                for source in sources:
                    with source.open('rb') as data:
                        shutil.copyfileobj(data, process.stdin)
                process.stdin.close()
                code = process.wait()
                if code:
                    raise subprocess.CalledProcessError(code, process.args)
            except BaseException:
                if process.poll() is None:
                    process.kill()
                process.wait()
                raise
            finally:
                if not process.stdin.closed:
                    process.stdin.close()
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['awk', 'script', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source', type=Path, action='append', required=True)
    parser.add_argument('--runtime', type=Path, action='append', default=[])
    args = parser.parse_args()
    try:
        merge(args.awk, args.script, args.source, args.output, args.runtime)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
