#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compile language boundary cases through the actual library with NODEV/NOSYS."""
from pathlib import Path
import ctypes as C
import json
import hashlib
import os
import struct
import sys
from dof_validation import validate_dof

if len(sys.argv) != 3:
    raise SystemExit('usage: compiler-offline.py /usr/obj/output /usr/obj/libdtrace.so.2')
out, binary = (Path(x).resolve() for x in sys.argv[1:])
if not all(p.is_relative_to('/usr/obj') for p in (out, binary)):
    raise SystemExit('Use isolated /usr/obj artifacts')
out.mkdir(parents=True, exist_ok=True)
lib = C.CDLL(str(binary))
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]
lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dtrace_program_strcompile.argtypes = [C.c_void_p, C.c_char_p, C.c_int, C.c_uint, C.c_int, C.c_void_p]
lib.dtrace_program_strcompile.restype = C.c_void_p
lib.dtrace_errno.argtypes = [C.c_void_p]
lib.dtrace_errno.restype = C.c_int
lib.dtrace_errmsg.argtypes = [C.c_void_p, C.c_int]
lib.dtrace_errmsg.restype = C.c_char_p
lib.dtrace_dof_create.argtypes = [C.c_void_p, C.c_void_p, C.c_uint]
lib.dtrace_dof_create.restype = C.c_void_p
lib.dtrace_dof_destroy.argtypes = [C.c_void_p, C.c_void_p]
valid = {
    # dt_grammar.y explicitly permits a trailing expression without ';'.
    'optional-final-semicolon': 'BEGIN { trace(1) }',
    'arithmetic': 'BEGIN { x = timestamp; trace((x + 3) * 7 - x / 2 + x % 3); }',
    'bitwise': 'BEGIN { x = timestamp; trace(((x << 2) | (x >> 1)) ^ (~x & 255)); }',
    'logical': 'BEGIN { x = timestamp; trace((x > 0 && x < 100) || x == 123); }',
    'comparisons': 'BEGIN { x = timestamp; trace(x <= 1); trace(x >= 1); trace(x != 1); }',
    'conditional': 'BEGIN { x = timestamp; trace(x ? 11 : 22); }',
    'compound': 'BEGIN { x = 7; x += 2; x -= 1; x *= 4; x /= 2; x %= 3; trace(x); }',
    'increment': 'BEGIN { x = 1; trace(x++); trace(++x); trace(x--); trace(--x); }',
    'casts': 'BEGIN { trace((int8_t)255); trace((uint64_t)1 << 40); trace((int64_t)-3); }',
    'typedef': 'typedef unsigned long counter_t; BEGIN { trace((counter_t)42); }',
    'enum': 'enum level { LOW = 2, HIGH = 9 }; BEGIN { trace(LOW); trace(HIGH); }',
    'local-global': 'BEGIN { self->value = 3; this->value = self->value + 4; trace(this->value); }',
    'associative-array': 'BEGIN { values[1, "key"] = 7; trace(values[1, "key"]); }',
    'aggregate-sum': 'BEGIN { @a[1] = sum(7); @b[1] = avg(8); }',
    'aggregate-range': 'BEGIN { @a = min(7); @b = max(8); @c = count(); }',
    'quantize': 'BEGIN { @a = quantize(13); @b = lquantize(4, 0, 16, 2); }',
    'strings': 'BEGIN { trace(strlen("abc")); trace(strjoin("ab", "cd")); }',
    'formats': 'BEGIN { printf("%d %x %s\\n", 12, 255, "text"); }',
    'predicate': 'BEGIN /timestamp != 0/ { trace(1); } END { trace(2); }',
    'sizeof': 'BEGIN { trace(sizeof(uint64_t)); trace(sizeof(char)); }',
    'comments': '/* before */ BEGIN { trace(1); /* after */ }',
}
invalid = {
    'missing-brace': 'BEGIN { trace(1);',
    'missing-separator': 'BEGIN { trace(1) trace(2); }',
    'unterminated-string': 'BEGIN { trace("broken); }',
    'unknown-type': 'BEGIN { trace((no_such_type_t)1); }',
    'non-lvalue': 'BEGIN { 1 = 2; }',
    'missing-expression': 'BEGIN { trace(1 + ); }',
    'unknown-call': 'BEGIN { no_such_function_97(); }',
    'bad-printf-type': 'BEGIN { printf("%d", "text"); }',
    'bad-printf-arity': 'BEGIN { printf("%d %d", 1); }',
    'bad-count-arity': 'BEGIN { @a = count(1); }',
    'duplicate-enumerator': 'enum e { SAME, SAME }; BEGIN { trace(1); }',
    'invalid-quantize-step': 'BEGIN { @a = lquantize(1, 0, 10, 0); }',
}
# Type construction and semantic rejection through the public compiler API.
valid.update({
    'struct-layout': 'struct pair { int left; long right; }; BEGIN { trace(sizeof(struct pair)); }',
    'union-layout': 'union bits { int word; char bytes[4]; }; BEGIN { trace(sizeof(union bits)); }',
    'array-typedef': 'typedef int values_t[4]; BEGIN { trace(sizeof(values_t)); }',
    'pointer-member': 'struct node { int value; struct node *next; }; BEGIN { this->p = (struct node *)0; trace(this->p->value); }',
    'pointer-arithmetic': 'BEGIN { this->p = (int *)0x1000; trace((uintptr_t)(this->p + 2)); trace((this->p + 2) - this->p); }',
    'array-index': 'BEGIN { this->p = (int *)0x1000; trace(this->p[3]); }',
    'inline-constant': 'inline int answer = 42; BEGIN { trace(answer); }',
    'enum-expression': 'enum flags { FIRST = 1, SECOND = FIRST << 2, THIRD }; BEGIN { trace(THIRD); }',
    'nested-struct': 'struct outer { struct { int value; } inner; }; BEGIN { trace(sizeof(struct outer)); }',
    'string-conditional': 'BEGIN { trace(timestamp ? "yes" : "no"); }',
    'compound-bitwise': 'BEGIN { x = 7; x <<= 2; x >>= 1; x |= 8; x &= 15; x ^= 3; trace(x); }',
    'aggregate-deviation': 'BEGIN { @a = stddev(12); }',
})
invalid.update({
    'incomplete-size': 'struct missing; BEGIN { trace(sizeof(struct missing)); }',
    'duplicate-member': 'struct pair { int member; int member; }; BEGIN { trace(1); }',
    'unknown-member': 'struct pair { int left; }; BEGIN { trace(((struct pair *)0)->right); }',
    'scalar-member': 'BEGIN { x = 1; trace(x.member); }',
    'scalar-dereference': 'BEGIN { x = 1; trace(*x); }',
    'array-of-void': 'typedef void bad_array[2]; BEGIN { trace(1); }',
    'unknown-size-type': 'BEGIN { trace(sizeof(unregistered_type)); }',
    'inline-type-mismatch': 'inline int value = "text"; BEGIN { trace(value); }',
    'string-multiplication': 'BEGIN { trace("left" * "right"); }',
    'void-value': 'BEGIN { trace((void)1); }',
})
valid.update({
    'aggregate-clear': 'BEGIN { @a = count(); clear(@a); }',
    'aggregate-normalize': 'BEGIN { @a = sum(9); normalize(@a, 3); denormalize(@a); }',
    'aggregate-truncate': 'BEGIN { @a[1] = count(); trunc(@a, 1); trunc(@a); }',
    'aggregate-print-default': 'BEGIN { @a[1] = count(); printa(@a); }',
    'aggregate-print-format': 'BEGIN { @a[1] = sum(9); printa("%d %@d", @a); }',
    'aggregate-print-multiple': 'BEGIN { @a[1] = sum(9); @b[1] = count(); printa("%d %@d %@d", @a, @b); }',
    'log-linear-quantize': 'BEGIN { @a = llquantize(42, 10, 0, 3, 20); }',
    'weighted-quantize': 'BEGIN { @a = quantize(42, 3); @b = lquantize(42, 0, 100, 10, 2); }',
    'format-width-precision': 'BEGIN { printf("%08x %.3s %*d", 255, "abcdef", 5, 12); }',
    'format-integer-widths': 'BEGIN { printf("%hd %ld %lld", (short)2, (long)3, (long long)4); }',
    'format-pointer': 'BEGIN { printf("%p", (void *)0x1000); }',
    'format-escaped-percent': 'BEGIN { printf("100%% complete"); }',
})
invalid.update({
    'clear-arity': 'BEGIN { clear(); }',
    'clear-scalar': 'BEGIN { clear(1); }',
    'clear-undefined': 'BEGIN { clear(@missing); }',
    'normalize-arity': 'BEGIN { @a = count(); normalize(@a); }',
    'normalize-scalar': 'BEGIN { normalize(1, 2); }',
    'normalize-string-divisor': 'BEGIN { @a = count(); normalize(@a, "two"); }',
    'normalize-undefined': 'BEGIN { normalize(@missing, 2); }',
    'denormalize-arity': 'BEGIN { @a = count(); denormalize(@a, 2); }',
    'trunc-scalar': 'BEGIN { trunc(1); }',
    'trunc-string-limit': 'BEGIN { @a = count(); trunc(@a, "two"); }',
    'trunc-undefined': 'BEGIN { trunc(@missing); }',
    'printa-scalar': 'BEGIN { printa(1); }',
    'printa-incompatible-keys': 'BEGIN { @a[1] = count(); @b["key"] = count(); printa(@a, @b); }',
    'llquant-small-factor': 'BEGIN { @a = llquantize(1, 1, 0, 3, 20); }',
    'llquant-magnitude-order': 'BEGIN { @a = llquantize(1, 10, 3, 2, 20); }',
    'llquant-small-steps': 'BEGIN { @a = llquantize(1, 10, 0, 3, 5); }',
    'llquant-indivisible-steps': 'BEGIN { @a = llquantize(1, 10, 0, 3, 21); }',
    'llquant-factor-overflow': 'BEGIN { @a = llquantize(1, 65536, 0, 3, 20); }',
    'llquant-nonconstant-factor': 'BEGIN { @a = llquantize(1, timestamp, 0, 3, 20); }',
    'format-incomplete': 'BEGIN { printf("%"); }',
    'format-unsupported': 'BEGIN { printf("%Q", 1); }',
    'format-width-type': 'BEGIN { printf("%*d", "width", 1); }',
})
invalid['format-unsupported-hh'] = 'BEGIN { printf("%hhd", (char)1); }'
expected_diagnostics = {
    'clear-arity': 'prototype mismatch',
    'clear-scalar': 'argument #1 is incompatible',
    'clear-undefined': 'failed to resolve @missing',
    'normalize-arity': 'prototype mismatch',
    'normalize-scalar': 'argument #1 is incompatible',
    'normalize-string-divisor': 'argument #2 must be of scalar type',
    'normalize-undefined': 'failed to resolve @missing',
    'denormalize-arity': 'prototype mismatch',
    'trunc-scalar': 'argument #1 is incompatible',
    'trunc-string-limit': 'argument #2 must be of scalar type',
    'trunc-undefined': 'failed to resolve @missing',
    'printa-scalar': 'argument #1 is incompatible',
    'printa-incompatible-keys': 'key #1 is incompatible',
    'llquant-small-factor': 'must be two or more',
    'llquant-magnitude-order': 'must be greater than low magnitude',
    'llquant-small-steps': 'must be less than or equal to the number',
    'llquant-indivisible-steps': 'must evenly divide',
    'llquant-factor-overflow': 'must be an unsigned 16-bit quantity',
    'llquant-nonconstant-factor': 'must be an integer constant',
    'format-incomplete': 'name expected before end of format string',
    'format-unsupported': 'is undefined: %Q',
    'format-width-type': 'argument #2 is incompatible',
    'format-unsupported-hh': 'is undefined: %hhd',
}
valid.update({
    'translator-scalar-member': 'struct result { int value; }; translator struct result < int source > { value = source + 7; }; BEGIN { trace(xlate <struct result>(3).value); }',
    'translator-pointer-input': 'struct input { int value; }; struct result { int value; }; translator struct result < struct input *source > { value = source->value; }; BEGIN { trace(xlate <struct result>((struct input *)0x1000).value); }',
    'translator-union-output': 'union result { int value; long wide; }; translator union result < int source > { value = source; wide = source + 1; }; BEGIN { trace(xlate <union result>(3).wide); }',
    'translator-multiple-members': 'struct result { int first; int second; }; translator struct result < int source > { first = source; second = source * 2; }; BEGIN { trace(xlate <struct result>(3).first); trace(xlate <struct result>(4).second); }',
    'translator-typedef-input': 'typedef int input_t; struct result { int value; }; translator struct result < input_t source > { value = source; }; BEGIN { trace(xlate <struct result>((input_t)4).value); }',
    'translator-declaration-only': 'struct result { int value; }; translator struct result < int source > { value = source; }; BEGIN { trace(1); }',
})
invalid.update({
    'translator-scalar-output': 'translator int < int source > { }; BEGIN { trace(1); }',
    'translator-unknown-member': 'struct result { int value; }; translator struct result < int source > { missing = source; }; BEGIN { trace(1); }',
    'translator-member-type': 'struct result { int value; }; translator struct result < int source > { value = "text"; }; BEGIN { trace(1); }',
    'translator-redeclaration': 'struct result { int value; }; translator struct result < int source > { value = source; }; translator struct result < int source > { value = source; }; BEGIN { trace(1); }',
    'translator-not-defined': 'struct result { int value; }; BEGIN { trace(xlate <struct result>(3).value); }',
    'translator-incomplete-output': 'struct result; translator struct result < int source > { value = source; }; BEGIN { trace(1); }',
})
expected_diagnostics.update({
    'translator-scalar-output': 'output type must be a struct or union',
    'translator-unknown-member': 'missing is not a member of struct result',
    'translator-member-type': 'definition uses incompatible types',
    'translator-redeclaration': 'has already been declared',
    'translator-not-defined': 'cannot translate from "int" to "struct result"',
    'translator-incomplete-output': 'incomplete struct/union/enum struct result',
})
results = []
for expected, corpus in ((True, valid), (False, invalid)):
    for name, source in corpus.items():
        error = C.c_int()
        h = lib.dtrace_open(3, 3, C.byref(error))  # NODEV | NOSYS
        if not h:
            raise SystemExit(f'NODEV open failed: {error.value}')
        try:
            program = lib.dtrace_program_strcompile(h, source.encode(), 4, 0x1004, 0, None)
            diagnostic = ''
            dof_summary = None
            if not program:
                diagnostic = lib.dtrace_errmsg(h, lib.dtrace_errno(h)).decode(errors='replace')
            passed = bool(program) == expected and (expected or bool(diagnostic))
            required_diagnostic = expected_diagnostics.get(name)
            if required_diagnostic:
                passed = passed and required_diagnostic in diagnostic
            if program:
                dof = lib.dtrace_dof_create(h, program, 1)
                assert dof
                try:
                    header = C.string_at(dof, 64)
                    assert header[:4] == b'\x7fDOF'
                    size = struct.unpack_from('<Q', header, 48)[0]
                    assert 64 <= size <= 64 * 1024 * 1024
                    data = C.string_at(dof, size)
                    dof_summary = validate_dof(data)
                    (out / (name + '.dof')).write_bytes(data)
                finally:
                    lib.dtrace_dof_destroy(h, dof)
            results.append({'case': name, 'source': source, 'expected_compile': expected,
                            'compiled': bool(program), 'diagnostic': diagnostic,
                            'required_diagnostic': required_diagnostic, 'dof': dof_summary, 'passed': passed})
        finally:
            lib.dtrace_close(h)
(out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
(out / 'provenance.json').write_text(json.dumps({'pid': os.getpid(), 'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'device_mode': 'NODEV | NOSYS'}, indent=2) + '\n')
failed = [r for r in results if not r['passed']]
for r in failed:
    print(json.dumps(r))
if failed:
    raise SystemExit(1)
print(f'PASS: {len(results)} actual compiler positive/negative cases; DOF checked; NODEV/NOSYS')
