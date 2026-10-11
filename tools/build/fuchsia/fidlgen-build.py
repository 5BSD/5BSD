#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Generate one FIDL binding set into the object tree (buildworld).

lib/libfidl/fidl-bindings.mk runs this for every FIDL_BINDINGS entry:
fidlc compiles the schemas (dependencies first, the library last) to JSON
IR, generate-bsd.py writes the native C++ and C bindings, and the result is
published under OUT so that unchanged files keep their modification times
(no needless recompiles) and concurrent runs from parallel bsd.progs.mk
recursions only ever replace whole files with identical ones.  STAMP is
touched last.  Python is a build-only tool; nothing here is installed.
"""
import argparse
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TEMPLATES = HERE.parents[2] / 'contrib/fuchsia/tools/fidl/fidlgen_cpp/codegen'


def load_generator():
    sys.path.insert(0, str(HERE))
    spec = importlib.util.spec_from_file_location('generate_bsd',
                                                  HERE / 'generate-bsd.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate(fidlc, schemas, flags, root):
    """Compile SCHEMAS and write the bindings below ROOT."""
    generator = load_generator()
    from generate_bsd_c import generate_c
    ir_path = root / 'ir.json'
    command = [fidlc, '--json', str(ir_path), *flags]
    for schema in schemas:
        command += ['--files', str(schema)]
    subprocess.run(command, check=True)
    tree = root / 'tree'
    ir, cpp = generator.generate(ir_path, tree, TEMPLATES)
    generate_c(ir, tree, cpp, [])
    return tree


def publish(tree, out):
    """Make OUT hold exactly TREE's files, replacing only changed ones."""
    wanted = {p.relative_to(tree) for p in tree.rglob('*') if p.is_file()}
    for relative in sorted(wanted):
        source, target = tree / relative, out / relative
        data = source.read_bytes()
        if target.is_file() and target.read_bytes() == data:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        # Same directory as the target, so the rename is atomic.
        fd, temporary = tempfile.mkstemp(prefix='.fidlgen-', dir=target.parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    if out.is_dir():
        for path in sorted(out.rglob('*'), reverse=True):
            relative = path.relative_to(out)
            # Only stale generated sources go: objects the build compiled
            # beside them stay.
            if path.is_file() and relative not in wanted and \
                    path.suffix in ('.h', '.cc') and \
                    not path.name.startswith('.fidlgen-'):
                path.unlink()
            elif path.is_dir() and not any(path.iterdir()):
                path.rmdir()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fidlc', default='fidlc')
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--stamp', type=Path)
    p.add_argument('--fidlc-flag', action='append', default=[],
                   help='extra fidlc argument, e.g. --fidlc-flag=--available '
                   '--fidlc-flag=bsd:2')
    p.add_argument('schemas', nargs='+', type=Path)
    a = p.parse_args()
    a.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix='.fidlgen-',
                                         dir=a.out.parent) as temporary:
            tree = generate(a.fidlc, a.schemas, a.fidlc_flag, Path(temporary))
            publish(tree, a.out)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        p.exit(1, f'{p.prog}: {", ".join(map(str, a.schemas))}: {error}\n')
    if a.stamp:
        a.stamp.touch()


if __name__ == '__main__':
    main()
