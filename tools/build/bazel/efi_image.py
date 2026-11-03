# SPDX-License-Identifier: BSD-2-Clause
"""Apply the maintained EFI nm/elfcopy recipe using explicit tools and runtimes."""
import argparse
from pathlib import Path
import subprocess


def environment(runtime, epoch):
    result = {'LC_ALL': 'C', 'SOURCE_DATE_EPOCH': epoch}
    if runtime:
        result['LD_LIBRARY_PATH'] = ':'.join(sorted({str(p.resolve(strict=True).parent) for p in runtime}))
    return result


def strong_undefined(text):
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 2 or len(fields[1]) != 1 or not fields[1].isalpha():
            raise ValueError('unrecognized POSIX nm record: ' + line)
        if fields[1] == 'U':
            result.append(fields[0])
    return result


def convert(args):
    source = args.src.resolve(strict=True)
    output = args.output.absolute()
    if source == output.resolve():
        raise ValueError('EFI input and output must differ')
    if not args.epoch.isascii() or not args.epoch.isdecimal() or not 0 <= int(args.epoch) <= 0xffffffff:
        raise ValueError('SOURCE_DATE_EPOCH must fit an unsigned PE timestamp')
    epoch = str(int(args.epoch))
    output.unlink(missing_ok=True)
    # Inspect both tables: stripping .symtab must not hide strong dynamic imports.
    undefined = set()
    for selection in ([], ['--dynamic']):
        check = subprocess.run([str(args.nm.resolve(strict=True)), '--format=posix', '--undefined-only',
                                *selection, str(source)], env=environment(args.nm_runtime, epoch),
                               text=True, capture_output=True, check=True)
        undefined.update(strong_undefined(check.stdout))
    if undefined:
        raise ValueError('Undefined symbols in EFI input: ' + ', '.join(sorted(undefined)))
    command = [str(args.objcopy.resolve(strict=True))]
    for section in args.section:
        command += ['-j', section]
    command += ['--output-target=' + args.format, str(source), str(output)]
    subprocess.run(command, env=environment(args.objcopy_runtime, epoch), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('src', 'output', 'nm', 'objcopy'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--format', required=True)
    parser.add_argument('--epoch', required=True)
    parser.add_argument('--section', required=True, action='append')
    parser.add_argument('--nm-runtime', nargs='*', type=Path, default=[])
    parser.add_argument('--objcopy-runtime', nargs='*', type=Path, default=[])
    args = parser.parse_args()
    try:
        convert(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
