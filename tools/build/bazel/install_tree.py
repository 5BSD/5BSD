# SPDX-License-Identifier: BSD-2-Clause
"""Serialize every file supplied by Bazel's declared tree-artifact expansion."""
import argparse
import json
from pathlib import Path, PurePosixPath
from archive_policy import resolve
from install_archive import normalized, write_archive


def relative(value):
    path = PurePosixPath(value)
    if value in ('', '.', '..') or path.is_absolute() or str(path) != value or '..' in path.parts or any(c.isspace() or c == '\\' for c in value):
        raise ValueError('non-normalized relative tree path: ' + value)
    return value


def installation_request(plan, tree_files):
    expected = {'format', 'tree', 'prefix', 'files', 'extra_directories', 'owner', 'group',
                'file_mode', 'directory_mode', 'file_tags', 'directory_tags', 'archive'}
    if set(plan) != expected or type(plan['format']) is not int or plan['format'] != 1:
        raise ValueError('exact installation tree plan format 1 required')
    prefix = plan['prefix']
    normalized(prefix)
    if prefix == '/':
        raise ValueError('generated installation tree needs a bounded destination prefix')
    for mode in [plan['file_mode'], plan['directory_mode']]:
        if not isinstance(mode, str) or not 3 <= len(mode) <= 4 or any(c not in '01234567' for c in mode):
            raise ValueError('explicit octal file and directory modes required')
    tree = PurePosixPath(plan['tree'])
    directories = {''}
    entries = {}

    def add_file(source, destination):
        destination = relative(destination)
        if destination in entries or destination in directories:
            raise ValueError('duplicate file or directory destination: ' + destination)
        if not Path(source).is_file():
            raise ValueError('declared tree payload is not a regular file: ' + source)
        entries[destination] = dict(destination=prefix + '/' + destination, source=source,
            type='file', owner=plan['owner'], group=plan['group'], mode=plan['file_mode'],
            flags='', tags=plan['file_tags'])
        parent = PurePosixPath(destination).parent
        while str(parent) != '.':
            if str(parent) in entries:
                raise ValueError('file used as installation directory: ' + str(parent))
            directories.add(str(parent))
            parent = parent.parent

    for source in sorted(tree_files):
        try:
            destination = PurePosixPath(source).relative_to(tree).as_posix()
        except ValueError as error:
            raise ValueError('expanded file outside declared tree: ' + source) from error
        add_file(source, destination)
    for item in plan['files']:
        if set(item) != {'source', 'destination'}:
            raise ValueError('exact additional payload source/destination required')
        add_file(item['source'], item['destination'])
    for directory in plan['extra_directories']:
        parent = PurePosixPath(relative(directory))
        while str(parent) != '.':
            if str(parent) in entries:
                raise ValueError('file used as compatibility directory: ' + str(parent))
            directories.add(str(parent))
            parent = parent.parent
    request = dict(plan['archive'])
    if request['records']:
        raise ValueError('tree archive base request must not hide additional records')
    request['records'] = [entries[path] for path in sorted(entries)] + [
        dict(destination=prefix + ('/' + path if path else ''), type='dir', owner=plan['owner'],
             group=plan['group'], mode=plan['directory_mode'], tags=plan['directory_tags'])
        for path in sorted(directories)]
    return request


def main():
    parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
    for name in ['plan', 'metadata', 'archive', 'directories']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--tree-file', action='append', default=[])
    args = parser.parse_args()
    request = installation_request(json.loads(args.plan.read_text()), args.tree_file)
    # Metadata exposes the complete payload inventory to normal stage/package
    # consumers. Mtree-only ancestors are resolved separately, as in static archives.
    resolved = resolve(request)
    write_archive(resolved, args.archive)
    selected = set(request.get('directory_packages', []))
    directories = [r for r in resolved['records'] if r['type'] == 'dir' and any(
        tag.startswith('package=') and tag[8:] in selected for tag in r.get('tags', []))]
    args.directories.write_text(json.dumps(dict(format=1, directories=directories, physical_directories=[r for r in resolved['records'] if r['type'] == 'dir']), sort_keys=True) + '\n')
    args.metadata.write_text(json.dumps(request, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
