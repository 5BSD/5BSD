#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Inspect actual XZ family artifacts; execute only native ABI programs."""
import argparse
import os
from pathlib import Path
import struct
import subprocess
import tempfile


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('program', 'static-program', 'decoder', 'info', 'shared', 'md-shared', 'archive', 'pic-archive', 'ar', 'nm'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--machine', type=int, choices=[62, 183, 243], required=True)
    a = p.parse_args()
    for path, kinds in [(a.program, [3]), (a.static_program, [2, 3]), (a.decoder, [3]), (a.info, [3]), (a.shared, [3])]:
        data = path.read_bytes()
        require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian required')
        kind, machine = struct.unpack_from('<HH', data, 16)
        require(kind in kinds and machine == a.machine, 'target architecture/type differs')
    names = ['tuklib_physmem', 'tuklib_cpucores', 'common', 'block_util', 'easy_preset', 'filter_common', 'hardware_physmem', 'hardware_cputhreads', 'index', 'stream_flags_common', 'string_conversion', 'vli_size', 'alone_encoder', 'block_buffer_encoder', 'block_encoder', 'block_header_encoder', 'easy_buffer_encoder', 'easy_encoder', 'easy_encoder_memusage', 'filter_buffer_encoder', 'filter_encoder', 'filter_flags_encoder', 'index_encoder', 'lzip_decoder', 'microlzma_encoder', 'microlzma_decoder', 'stream_buffer_encoder', 'stream_encoder', 'stream_flags_encoder', 'vli_encoder', 'alone_decoder', 'auto_decoder', 'block_buffer_decoder', 'block_decoder', 'block_header_decoder', 'easy_decoder_memusage', 'file_info', 'filter_buffer_decoder', 'filter_decoder', 'filter_flags_decoder', 'index_decoder', 'index_hash', 'stream_buffer_decoder', 'stream_decoder', 'stream_decoder_mt', 'stream_flags_decoder', 'stream_encoder_mt', 'vli_decoder', 'outqueue', 'check', 'crc32_fast', 'crc64_fast', 'lz_encoder', 'lz_encoder_mf', 'lz_decoder', 'lzma_encoder', 'lzma_encoder_presets', 'lzma_encoder_optimum_fast', 'lzma_encoder_optimum_normal', 'fastpos_table', 'lzma_decoder', 'lzma2_encoder', 'lzma2_decoder', 'price_table', 'delta_common', 'delta_encoder', 'delta_decoder', 'simple_coder', 'simple_encoder', 'simple_decoder', 'x86', 'powerpc', 'ia64', 'arm', 'arm64', 'armthumb', 'riscv', 'sparc']
    for path, suffix in [(a.archive, '.o'), (a.pic_archive, '.pic.o')]:
        members = subprocess.check_output([a.ar, 't', path], text=True).splitlines()
        require(members == [n + suffix for n in names], 'original archive member order differs')
    symbols = subprocess.check_output([a.nm, '--format=posix', '--extern-only', '--defined-only', a.static_program], text=True)
    defined = {line.split()[0] for line in symbols.splitlines() if line.split()}
    require({'lzma_version_number', 'lzma_code', 'lzma_end'} <= defined, 'real static XZ failed to extract required APIs')
    require('lzma_microlzma_encoder' not in defined, 'static XZ forced unrelated microlzma archive member')
    if a.machine == 62:
        env = dict(os.environ, LC_ALL='C', LD_LIBRARY_PATH=':'.join({str(a.shared.resolve().parent), str(a.md_shared.resolve().parent)}))
        sample = bytes(range(256)) * 4096
        def run(program, args, data):
            return subprocess.check_output([program, *args], input=data, env=env)
        encoded = run(a.program, ['-c', '-T1', '--check=sha256'], sample)
        require(run(a.static_program, ['-dc'], encoded) == sample, 'real static XZ decode differs')
        alone = run(a.program, ['-c', '-T1', '--format=lzma'], sample)
        with tempfile.TemporaryDirectory(prefix='xz-family-') as temp:
            for name in ['xz', 'unxz', 'xzcat', 'lzma', 'unlzma', 'lzcat']:
                program = Path(temp) / name
                program.symlink_to(a.program.resolve())
                stream = alone if name in ['lzma', 'unlzma', 'lzcat'] else encoded
                args = ['-c'] + (['-d'] if name in ['xz', 'lzma'] else [])
                require(run(program, args, stream) == sample, 'command alias decode differs: ' + name)
            for name in ['xzdec', 'lzdec']:
                program = Path(temp) / name
                program.symlink_to(a.decoder.resolve())
                require(run(program, [], encoded) == sample, 'original decoder alias differs: ' + name)
        info = run(a.info, [], alone)
        require(bool(info.strip()), 'lzmainfo failed to inspect original-format stream')
        rejected = subprocess.run([a.program, '-dc'], input=encoded[:-3], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        require(rejected.returncode != 0, 'truncated XZ input accepted')
    print('XZ target ABI, original archive order, real static extraction and native-only family checks: passed')


if __name__ == '__main__':
    main()
