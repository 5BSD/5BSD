# SPDX-License-Identifier: BSD-2-Clause
"""Strip a BIOS ELF client and enforce its declared size before publishing output."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def strip_image(source, output, strip, maximum, runtime):
    if maximum <= 0:
        raise ValueError('boot client size limit must be positive')
    if source.resolve(strict=True) == output.resolve():
        raise ValueError('boot client input and output must differ')
    env = {'LC_ALL': 'C'}
    libraries = {str(p.resolve(strict=True).parent) for p in runtime
                 if p.name.endswith('.so') or '.so.' in p.name}
    if libraries:
        env['LD_LIBRARY_PATH'] = ':'.join(sorted(libraries))
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix=output.name + '.', delete=False) as temporary:
        path = Path(temporary.name)
    try:
        subprocess.run([str(strip), '-R', '.comment', '-R', '.note', '-R', '.gnu_debuglink', '-o', str(path), str(source)],
                       env=env, check=True, capture_output=True)
        size = path.stat().st_size
        if size > maximum:
            raise ValueError(f'boot client exceeds its declared size limit: {size} > {maximum}')
        os.replace(path, output)
    finally:
        path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'output', 'strip']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--max-size', type=int, required=True)
    parser.add_argument('--runtime', type=Path, nargs='*', default=[])
    args = parser.parse_args()
    try:
        strip_image(args.source, args.output, args.strip, args.max_size, args.runtime)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
