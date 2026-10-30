# SPDX-License-Identifier: BSD-2-Clause
"""Shared explicit Python/ELF staging for disposable verifier fixtures."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class Fixture:
    def __init__(self, world, prefix, extra):
        self.world, self.prefix, self.extra = world, prefix, extra
        self.source_hashes, self.seen, self.dependencies = {}, set(), {}
        source = Path(__file__).resolve()
        self.source_hashes[str(source)] = hashlib.sha256(source.read_bytes()).hexdigest()

    def copy(self, source, destination, boundary):
        source_hashes = self.source_hashes
        source = source.resolve(strict=True)
        if not source.is_relative_to(boundary):
            raise ValueError('fixture input escapes selected root: ' + str(source))
        expected = file_hash(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if file_hash(destination) != expected:
                raise ValueError('conflicting fixture input: ' + str(destination))
        else:
            shutil.copyfile(source, destination)
        if any(file_hash(p) != expected
               for p in (source, destination)):
            raise ValueError('fixture input changed: ' + str(source))
        source_hashes[str(source)] = expected

    def elf(self, source, relative, boundary):
        seen, dependencies = self.seen, self.dependencies
        world, prefix, extra = self.world, self.prefix, self.extra
        copy, elf = self.copy, self.elf
        if relative in seen:
            return
        seen.add(relative)
        dependencies[relative] = set()
        copy(source, extra / relative, boundary)
        headers = subprocess.check_output(['readelf', '-l', str(source)], text=True)
        for interpreter in re.findall(r'Requesting program interpreter: ([^\]]+)', headers):
            dependencies[relative].add(interpreter.lstrip('/'))
            elf(world / interpreter.lstrip('/'), interpreter.lstrip('/'), world)
        dynamic = subprocess.check_output(['readelf', '-d', str(source)], text=True)
        for search in re.findall(r'\((?:RPATH|RUNPATH)\).*\[([^\]]*)\]', dynamic):
            if any(p not in ('/lib', '/usr/lib', '/usr/local/lib') for p in search.split(':')):
                raise ValueError('unsupported fixture runtime search path: ' + search)
        for library in re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic):
            if '/' in library:
                raise ValueError('unsupported ELF dependency path')
            matches = [(world / p / library, p + '/' + library, world)
                       for p in ('lib', 'usr/lib') if (world / p / library).is_file()]
            if (prefix / 'lib' / library).is_file():
                matches.append((prefix / 'lib' / library, 'usr/local/lib/' + library, prefix))
            if len(matches) != 1:
                raise ValueError('missing or ambiguous explicit library: ' + library)
            dependencies[relative].add(matches[0][1])
            elf(*matches[0])

    def backend_python(self, backend):
        """Stage the complete selected flat Python backend, including new modules.

        This is fixture tooling, not a selected OS payload inventory. Every copied
        module remains bound by source/staged hashes through copy().
        """
        backend = Path(backend).resolve(strict=True)
        modules = sorted(backend.glob('*.py'))
        if not modules:
            raise ValueError('selected Python backend has no modules')
        for source in modules:
            if source.is_symlink() or not source.is_file():
                raise ValueError('backend modules must be regular nonsymlink files')
            self.copy(source, self.extra / 'tests' / source.name, backend)

    def python(self):
        prefix, extra = self.prefix, self.extra
        copy, elf = self.copy, self.elf
        # Explicit Python distribution and its dependencies are fixture inputs.
        # All standard-library modules are staged; package inventory is not inferred
        # from this selected mechanism image.
        elf(prefix / 'bin/python3.12', 'usr/local/bin/python3.12', prefix)
        standard = prefix / 'lib/python3.12'
        for source in sorted(standard.rglob('*')):
            relative = source.relative_to(standard)
            if any(p in ('site-packages', '__pycache__', 'config-3.12') for p in relative.parts):
                continue
            if source.is_dir():
                continue
            destination = 'usr/local/lib/python3.12/' + str(relative)
            if source.suffix == '.so':
                elf(source, destination, prefix)
            else:
                copy(source, extra / destination, prefix)
