#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile, serialize and parse programs using NODEV/NOSYS; never enable probes."""
import ctypes as C
import os, sys, struct, hashlib
from pathlib import Path
if len(sys.argv) != 4: raise SystemExit('usage: elf-roundtrip.py OUT LIB INSPECTOR')
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
lib = C.CDLL(str(Path(sys.argv[2]).resolve()))
inspector = C.CDLL(str(Path(sys.argv[3]).resolve()))
inspector.hypertrace_test_format.argtypes = [C.c_void_p]
inspector.hypertrace_test_format.restype = C.c_int
inspector.hypertrace_test_fmtdata.argtypes = [C.c_void_p]
inspector.hypertrace_test_fmtdata.restype = C.c_void_p
inspector.hypertrace_test_rflags.argtypes = [C.c_void_p]
inspector.hypertrace_test_rflags.restype = C.c_uint32
lib.dtrace_printf_format.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t]
lib.dtrace_printf_format.restype = C.c_size_t
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_uint, C.c_int, C.c_void_p]
lib.dtrace_program_strcompile.restype = C.c_void_p
lib.dtrace_vprog_from.argtypes = [C.c_void_p, C.c_void_p, C.c_int]
lib.dtrace_vprog_from.restype = C.c_void_p
lib.dt_verictx_init.argtypes = [C.c_void_p]
lib.dt_verictx_init.restype = C.c_void_p
lib.dt_verictx_teardown.argtypes = [C.c_void_p]
lib.dt_prog_verify.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
lib.dt_prog_verify.restype = C.c_int
lib.dtrace_errno.argtypes = [C.c_void_p]; lib.dtrace_errno.restype = C.c_int
lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]; lib.dtrace_errmsg.restype = C.c_char_p
lib.dtrace_elf_create.argtypes = [C.c_void_p, C.c_void_p, C.c_int, C.c_int, C.c_char_p, C.c_char_p]
lib.dtrace_elf_create.restype = C.c_int
lib.dtrace_elf_parse.argtypes = [C.c_void_p, C.c_int, C.c_char_p, C.c_int, C.POINTER(C.c_int), C.c_char_p, C.c_void_p]
lib.dtrace_elf_parse.restype = C.c_void_p
lib.dtrace_dof_create.argtypes = [C.c_void_p, C.c_void_p, C.c_uint]
lib.dtrace_dof_create.restype = C.c_void_p
lib.dtrace_dof_destroy.argtypes = [C.c_void_p, C.c_void_p]
error = C.c_int()
hdl = lib.dtrace_open(3, 3, C.byref(error))  # VERSION 3; NODEV | NOSYS
assert hdl, ('dtrace_open', error.value, lib.dtrace_errmsg(None, error.value))
cases = [b'BEGIN { trace(1); }', b'BEGIN { printf("value=%d\\n", 42); }',
         b'BEGIN { trace(2); trace(3); } END { trace(4); }',
         b'BEGIN { @counts[1] = count(); }',
         b'BEGIN { x = 1; trace(x); }',
         b'BEGIN { this->x = timestamp; trace(this->x); }',
         b'BEGIN { trace(timestamp); trace(vtimestamp); '
         b'trace(walltimestamp); }']
def section_entries(content):
    assert content[:6] == b'\x7fELF\x01\x01'
    start = struct.unpack_from('<I', content, 32)[0]
    width = struct.unpack_from('<H', content, 46)[0]
    count = struct.unpack_from('<I', content, start + 20)[0]
    records = [struct.unpack_from('<10I', content, start + i * width) for i in range(count)]
    names = content[records[1][4]:records[1][4] + records[1][5]]
    return [(names[r[0]:].split(b'\0', 1)[0], i, r[4], r[5])
            for i, r in enumerate(records) if i]
def sections(content):
    return {name: (i, offset, size)
            for name, i, offset, size in reversed(section_entries(content))}
def change(content, offset, value, code='<I'):
    result = bytearray(content); struct.pack_into(code, result, offset, value); return bytes(result)
def parse_file(path, content, original, expected=None):
    path.write_bytes(content)
    fd = os.open(path, os.O_RDONLY)
    try:
        message = C.create_string_buffer(512)
        parsed = lib.dtrace_elf_parse(hdl, fd, os.fsencode(path), 0, C.byref(error), message, original)
        if expected is None:
            assert parsed, ('parse', error.value, message.value)
        else:
            assert not parsed and expected in message.value, ('malformed', path, error.value, message.value)
        return parsed
    finally: os.close(fd)
rejections = 0
try:
    for i, source in enumerate(cases):
        program = lib.dtrace_program_strcompile(hdl, source, 4, 0x1004, 0, None) # NAME; NOLIBS | ZDEFS
        assert program, ('compile', source, lib.dtrace_errmsg(hdl, lib.dtrace_errno(hdl)))
        path = out / f'program-{i}.elf'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            message = C.create_string_buffer(512)
            result = lib.dtrace_elf_create(hdl, program, 1, fd, os.fsencode(path), message) # ELFDATA2LSB
            assert result == 0, ('create', result, message.value)
            parsed = lib.dtrace_elf_parse(hdl, fd, os.fsencode(path), 0, C.byref(error), message, program)
            assert parsed, ('parse', error.value, message.value)
            if i == 1:
                assert inspector.hypertrace_test_format(parsed), 'printf conversion lost in ELF round trip'
                dof = lib.dtrace_dof_create(hdl, parsed, 0)
                assert dof, ('printf DOF', lib.dtrace_errno(hdl))
                lib.dtrace_dof_destroy(hdl, dof)
        finally: os.close(fd)
        content = path.read_bytes()
        if i == 0:
            _, program_offset, _ = sections(content)[b'.dtrace_prog']
            old_flags = struct.unpack_from('<I', content,
                program_offset + 12)[0]
            new_flags = old_flags ^ 1
            changed_flags = parse_file(out / 'changed-resolver-flags.elf',
                change(content, program_offset + 12, new_flags), program)
            assert inspector.hypertrace_test_rflags(changed_flags) == \
                new_flags, 'ELF parser dropped resolver flags'
            verify = lib.dt_verictx_init(hdl)
            assert verify, 'resolver flag verifier allocation'
            try:
                assert lib.dt_prog_verify(verify, program, changed_flags) != 0, \
                    'changed resolver flags were accepted'
            finally:
                lib.dt_verictx_teardown(verify)
        if i == 6:
            verify = lib.dt_verictx_init(hdl)
            assert verify, 'host response verifier allocation'
            assert lib.dt_prog_verify(verify, program, parsed) == 0, \
                'valid host response failed verification'
            forwarding = lib.dtrace_vprog_from(hdl, parsed, 0)
            assert forwarding, ('vtime forwarding', lib.dtrace_errmsg(hdl,
                lib.dtrace_errno(hdl)))
            forwarded_path = out / 'program-vtime-forwarding.elf'
            forwarded_fd = os.open(forwarded_path,
                os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                message = C.create_string_buffer(512)
                result = lib.dtrace_elf_create(hdl, forwarding, 1,
                    forwarded_fd, os.fsencode(forwarded_path), message)
                assert result == 0, ('vtime forwarding create', result,
                    message.value)
                guest_response = lib.dtrace_elf_parse(hdl, forwarded_fd,
                    os.fsencode(forwarded_path), 0, C.byref(error),
                    message, forwarding)
                assert guest_response, ('vtime forwarding parse', error.value,
                    message.value)
                assert lib.dt_prog_verify(verify, forwarding,
                    guest_response) == 0, \
                    'valid guest forwarding response failed verification'
                lib.dt_verictx_teardown(verify)
                dof = lib.dtrace_dof_create(hdl, guest_response, 0)
                assert dof, ('vtime forwarding DOF', lib.dtrace_errno(hdl))
                lib.dtrace_dof_destroy(hdl, dof)
            finally: os.close(forwarded_fd)
            forwarded = forwarded_path.read_bytes()
            _, action_offset, _ = sections(forwarded)[b'.dtrace_actdesc']
            changed = parse_file(out / 'changed-guest-response.elf',
                change(forwarded, action_offset + 24, 1, '<Q'), forwarding)
            verify = lib.dt_verictx_init(hdl)
            assert verify, 'changed guest response verifier allocation'
            try:
                assert lib.dt_prog_verify(verify, forwarding, changed) != 0, \
                    'changed guest response action was accepted'
            finally:
                lib.dt_verictx_teardown(verify)
        checked = parse_file(out / f'checksummed-{i}.elf',
                             hashlib.sha256(content).digest() + content, program)
        if i == 1:
            assert inspector.hypertrace_test_format(checked), 'checksummed printf conversion lost'
        layout = sections(content)
        stmt_id, stmt_offset, stmt_size = layout[b'.dtrace_stmtdesc']
        bad = change(content, stmt_offset + stmt_size - 8, stmt_id)
        parse_file(out / f'cyclic-statements-{i}.elf', bad, program, b'cyclic statement')
        rejections += 1
        if i == 0:
            assert struct.unpack_from('<I', content,
                stmt_offset + stmt_size - 4)[0] == stmt_id
            bad = change(content, stmt_offset + stmt_size - 4, 0)
            parse_file(out / 'wrong-statement-self.elf', bad, program,
                       b'statement self reference mismatch')
            rejections += 1
            action_id, action_offset, _ = layout[b'.dtrace_actdesc']
            assert action_id and struct.unpack_from('<Q', content,
                action_offset + 32)[0] == stmt_id
            bad = change(content, action_offset + 32, 0, '<Q')
            parse_file(out / 'wrong-action-owner.elf', bad, program,
                       b'action statement reference mismatch')
            rejections += 1
            for label, offset, value, code in (
                    ('unknown-action-kind', 8, 0xffffffff, '<I'),
                    ('action-class-marker', 8, 0x0600, '<I'),
                    ('oversized-action-tuple', 16, 1 << 32, '<Q'),
                    ('nonaggregate-action-tuple', 16, 1, '<Q'),
                    ('invalid-action-return', 40, 2, '<i')):
                bad = change(content, action_offset + offset, value, code)
                parse_file(out / f'{label}.elf', bad, program,
                           b'invalid serialized action fields')
                rejections += 1
        if i == 1:
            _, format_offset, format_size = layout[b'.dtrace_pfv_argv']
            assert format_size >= 48
            assert struct.unpack_from('<I', content, format_offset + 40)[0] != 0
            bad = change(content, format_offset + 40, 0)
            parse_file(out / 'missing-format-conversion.elf', bad, program,
                       b'missing format conversion')
            rejections += 1
            bad = change(content, format_offset + 40, 0xffffffff)
            parse_file(out / 'invalid-format-conversion.elf', bad, program,
                       b'invalid format conversion')
            rejections += 1
            wide = change(content, format_offset + 28, 2147483647)
            parsed_wide = parse_file(out / 'wide-format.elf', wide, program)
            fmtdata = inspector.hypertrace_test_fmtdata(parsed_wide)
            assert fmtdata
            rendered = C.create_string_buffer(128)
            n = lib.dtrace_printf_format(hdl, fmtdata, rendered, len(rendered))
            assert n < len(rendered) and b'2147483647' in rendered.value
            bounded = C.create_string_buffer(16)
            bounded.raw = b'Q' * 16
            assert lib.dtrace_printf_format(hdl, fmtdata, bounded, 4) == n
            assert bounded.raw[4:] == b'Q' * 12
            dof = lib.dtrace_dof_create(hdl, parsed_wide, 0)
            assert dof, ('wide printf DOF', lib.dtrace_errno(hdl))
            lib.dtrace_dof_destroy(hdl, dof)
            _, fmtdata_offset, fmtdata_size = layout[b'.dtrace_fmtdata']
            assert fmtdata_size >= 20
            bad = change(content, fmtdata_offset + 12, 1)
            parse_file(out / 'wrong-format-argument-count.elf', bad, program,
                       b'format argument count mismatch')
            rejections += 1
            bad = change(content, fmtdata_offset + 16, 0x80000000)
            parse_file(out / 'unknown-format-flags.elf', bad, program,
                       b'invalid format argument count or flags')
            rejections += 1
        _, difo_offset, _ = layout[b'.dtrace_difo']
        bad = change(content, difo_offset + 16, 0xffffffffffffffff, '<Q')
        parse_file(out / f'oversized-integer-table-{i}.elf', bad, program, b'DIF table')
        rejections += 1
        # The 72-byte DIFO header stores its eight-byte return type at 48.
        for name, field, value in [('bad-return-kind', 0, 0x7f),
                                   ('bad-return-flags', 2, 0x80),
                                   ('bad-return-padding', 3, 1)]:
            bad = bytearray(content)
            bad[difo_offset + 48 + field] = value
            parse_file(out / f'{name}-{i}.elf', bytes(bad), program,
                       b'invalid DIF return type')
            rejections += 1
        # dt_elf_difo_t's instruction array follows its 72-byte header.
        for name, instruction in [('bad-setx', (37 << 24) | (0xffff << 8) | 1),
                                  ('bad-branch', (17 << 24) | 0xffffff),
                                  ('bad-opcode', 0xff000000)]:
            bad = change(content, difo_offset + 72, instruction)
            parse_file(out / f'{name}-{i}.elf', bad, program, b'invalid DIF instruction reference')
            rejections += 1
        if i == len(cases) - 1:
            # The native dtrace_difv_t is 136 bytes in this amd64 writer.
            # Compiler-owned pointers sit at 32, 104, 112 and 120.
            vartab_id, vartab_offset, vartab_size = layout[b'.dtrace_vartab']
            assert vartab_size and vartab_size % 136 == 0
            for item in range(vartab_size // 136):
                record = vartab_offset + item * 136
                for field in (32, 104, 112, 120):
                    assert content[record + field:record + field + 8] == bytes(8), 'writer serialized a process pointer'
            bad = change(content, vartab_offset, 0xffffffff)
            parse_file(out / 'invalid-variable-name.elf', bad, program, b'invalid DIF variable string')
            rejections += 1
            bad = bytearray(content)
            bad[vartab_offset + 40:vartab_offset + 104] = b'X' * 64
            parse_file(out / 'unterminated-variable-object.elf', bytes(bad), program, b'invalid DIF variable string')
            rejections += 1
            # The variable's DIF type starts at byte 12 of its record.
            for name, field, value in [('bad-variable-kind', 0, 0x7f),
                                       ('bad-variable-flags', 2, 0x80),
                                       ('bad-variable-padding', 3, 1)]:
                bad = bytearray(content)
                bad[vartab_offset + 12 + field] = value
                parse_file(out / f'{name}.elf', bytes(bad), program,
                           b'invalid DIF variable type')
                rejections += 1
            # A foreign pointer in an input file must be ignored and replaced.
            bad = change(content, vartab_offset + 32, 0xdeadbeefdeadbeef, '<Q')
            parse_file(out / 'foreign-variable-pointer.elf', bad, program)
        if i == 2:
            action_id, action_offset, _ = layout[b'.dtrace_actdesc']
            statement_ids = [section_id for name, section_id, _, _ in
                             section_entries(content) if name == b'.dtrace_stmtdesc']
            assert len(statement_ids) > 1 and statement_ids[-1] != stmt_id
            bad = change(content, action_offset + 32, statement_ids[-1], '<Q')
            parse_file(out / 'wrong-valid-action-owner.elf', bad, program,
                       b'action statement reference mismatch')
            rejections += 1
            second_stmt_offset = next(offset for _, section_id, offset, _ in
                                      section_entries(content)
                                      if section_id == statement_ids[1])
            foreign_stmt_offset = next(offset for _, section_id, offset, _ in
                                       section_entries(content)
                                       if section_id == statement_ids[-1])
            successor_id = struct.unpack_from('<I', content,
                                              second_stmt_offset + 4)[0]
            foreign_id = struct.unpack_from('<I', content,
                                            foreign_stmt_offset + 4)[0]
            assert successor_id != foreign_id and successor_id != action_id
            for name, target in [('missing', 0), ('foreign', foreign_id)]:
                bad = change(content, action_offset + 4, target)
                parse_file(out / f'{name}-action-successor.elf', bad,
                           program, b'action successor mismatch')
                rejections += 1
            bad = change(content, action_offset + 4, action_id)
            bad = change(bad, stmt_offset + 8, 0)  # Make the declared end unreachable.
            parse_file(out / 'cyclic-actions.elf', bad, program,
                       b'invalid statement action graph')
            rejections += 1
            last_id = struct.unpack_from('<I', content, stmt_offset + 8)[0]
            last_offset = next(offset for _, section_id, offset, _ in
                               section_entries(content) if section_id == last_id)
            bad = change(content, last_offset + 4, last_id)
            parse_file(out / 'cyclic-terminal-self.elf', bad,
                       program, b'action successor mismatch')
            rejections += 1
            second_action_offset = next(offset for _, section_id, offset, _ in
                                        section_entries(content)
                                        if section_id == successor_id)
            bad = change(content, second_action_offset + 4, foreign_id)
            parse_file(out / 'dangling-action-successor.elf', bad,
                       program, b'dangling action successor')
            rejections += 1
        if i == 3:
            first_id = struct.unpack_from('<I', content, stmt_offset + 4)[0]
            last_id = struct.unpack_from('<I', content, stmt_offset + 8)[0]
            assert first_id != last_id, 'expected multi-action aggregation span'
            last_offset = next(offset for _, section_id, offset, _ in
                               section_entries(content) if section_id == last_id)
            bad = change(content, last_offset + 4, first_id)
            parse_file(out / 'cyclic-terminal-backedge.elf', bad,
                       program, b'dangling action successor')
            rejections += 1
finally: lib.dtrace_close(hdl)
print(f'PASS: {len(cases)} valid compile/write/read ELF round trips plus checksummed variants and {rejections} malformed graph/table rejections with NODEV and NOSYS')
