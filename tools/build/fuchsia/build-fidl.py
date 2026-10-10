#!/usr/bin/env python3.12
"""Build the imported upstream FIDL host tools and compiler tests on 5BSD."""
import argparse
import concurrent.futures
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--src', type=Path, default=Path('/usr/src'))
parser.add_argument('--obj', type=Path, default=Path('/usr/obj/5bsd-fidl'))
parser.add_argument('--test', action='store_true')
parser.add_argument('--test-only', action='store_true', help='run already built compiler tests')
args = parser.parse_args()
root = args.src / 'contrib/fuchsia'
obj = args.obj.resolve()
obj.mkdir(parents=True, exist_ok=True)
fidl = root / 'tools/fidl/fidlc'
gtest = args.src / 'contrib/googletest'
includes = [root, root / 'sdk/lib/fit/include', root / 'sdk/lib/stdcompat/include',
            root / 'src/lib/cmdline/include', root / 'zircon/system/public',
            gtest / 'googletest/include', gtest / 'googletest',
            gtest / 'googlemock/include', gtest / 'googlemock', Path('/usr/local/include')]
flags = ['-std=c++20', '-O1', '-g', '-pthread']
flags += ['-I' + str(p) for p in includes]
flags += ['-DTEST_DATA_ROOT="' + str(obj) + '"']
cxx = os.environ.get('CXX', 'c++')
schema = obj / 'json_schema.cc'
subprocess.run(['sh', str(fidl / 'gen-json-schema.sh'), str(schema),
                str(fidl / 'schema.json')], check=True)
core = sorted((fidl / 'src').glob('*.cc'))
core += [schema, root / 'src/lib/cmdline/args_parser.cc',
         root / 'sdk/lib/zircon-assert/zx_panic_libc.cc']
core += [p for p in (root / 'src/lib/fxl/strings').glob('*.cc')
         if not p.name.endswith('_unittest.cc')]
core += [root / 'src/lib/fxl/third_party/icu/icu_utf.cc']
programs = {name: list((fidl / 'cmd' / name).glob('*.cc'))
            for name in ['fidlc', 'fidl-format', 'fidl-lint']}
if args.test or args.test_only:
    programs['fidlc-test'] = list((fidl / 'tests').glob('*.cc')) + [
        gtest / 'googletest/src/gtest-all.cc', gtest / 'googletest/src/gtest_main.cc',
        gtest / 'googlemock/src/gmock-all.cc',
        args.src / 'tools/build/fuchsia/lexer_test.cc']
sources = core + [s for group in programs.values() for s in group]

def object_path(source):
    import hashlib
    return obj / (source.stem + '-' + hashlib.sha256(str(source).encode()).hexdigest()[:12] + '.o')

def compile_one(source):
    target = object_path(source)
    log = target.with_suffix('.log')
    with log.open('w') as stream:
        result = subprocess.run([cxx, *flags, '-c', str(source), '-o', str(target)],
                                stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(str(source) + '\n' + log.read_text())

if not args.test_only:
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        list(pool.map(compile_one, sources))
    for name, extra in programs.items():
        subprocess.run([cxx, '-pthread', *map(str, map(object_path, core + extra)),
                        '-L/usr/local/lib', '-Wl,-rpath,/usr/local/lib', '-lre2', '-lcrypto',
                        '-o', str(obj / name)], check=True)
        print('Built ' + str(obj / name), flush=True)
if args.test or args.test_only:
    data = obj / 'fidlc-tests'
    data.mkdir(exist_ok=True)
    for kind in ['bad', 'good']:
        shutil.copytree(fidl / 'tests/fidl' / kind, data / kind, dirs_exist_ok=True)
    shutil.copytree(root / 'docs/reference/fidl/language/error-catalog',
                    data / 'error-catalog', dirs_exist_ok=True)
    for source in [root / 'docs/error/_redirects.yaml',
                   root / 'docs/reference/fidl/language/errcat.md',
                   fidl / 'tests/errcat_good_tests.cc']:
        shutil.copy2(source, data)
    subprocess.run([str(obj / 'fidlc-test'),
                    '--gtest_output=xml:' + str(obj / 'fidlc-test.xml')], check=True, cwd=obj)
