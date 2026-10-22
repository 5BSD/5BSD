#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run under the test interposer, using a plain trace(1) ELF fixture."""
import ctypes as C
import os, sys
from pathlib import Path
hooks = C.CDLL(None)
hooks.elf_test_arm.argtypes = [C.c_int]
hooks.elf_test_disarm.restype = C.c_int
hooks.elf_test_attempts.restype = C.c_int
lib = C.CDLL(str(Path(sys.argv[1]).resolve()), mode=C.RTLD_GLOBAL)
lib.dtrace_open.argtypes = [C.c_int, C.c_int, C.POINTER(C.c_int)]; lib.dtrace_open.restype = C.c_void_p
lib.dtrace_close.argtypes = [C.c_void_p]
lib.dt_program_destroy.argtypes = [C.c_void_p, C.c_void_p]
lib.dtrace_elf_parse.argtypes = [C.c_void_p, C.c_int, C.c_char_p, C.c_int, C.POINTER(C.c_int), C.c_char_p, C.c_void_p]
lib.dtrace_elf_parse.restype = C.c_void_p
path = Path(sys.argv[2]).resolve()
error = C.c_int(); handle = lib.dtrace_open(3, 3, C.byref(error))
assert handle, ('open', error.value)
try:
    # Initialize process-lifetime C++ lookup tables before per-parse accounting.
    warmfd = os.open(path, os.O_RDONLY)
    try:
        warmmsg = C.create_string_buffer(512)
        warm = lib.dtrace_elf_parse(handle, warmfd, os.fsencode(path), 0,
                                   C.byref(error), warmmsg, None)
        assert warm, ('warmup parse', error.value, warmmsg.value)
        lib.dt_program_destroy(handle, warm)
    finally: os.close(warmfd)
    failures = 0
    for fail in range(128):
        fd = os.open(path, os.O_RDONLY); message = C.create_string_buffer(512)
        hooks.elf_test_arm(fail)
        try:
            program = lib.dtrace_elf_parse(handle, fd, os.fsencode(path), 0, C.byref(error), message, None)
            if program: lib.dt_program_destroy(handle, program)
        finally: os.close(fd)
        attempts = hooks.elf_test_attempts(); live = hooks.elf_test_disarm()
        assert live == 0, ('leaked allocations', fail, live, error.value, message.value)
        if program:
            assert attempts > 0, 'allocation hooks did not intercept the parser'
            break
        failures += 1
        assert error.value != 0, ('missing error', fail)
    else: raise AssertionError('no successful parse')
finally: lib.dtrace_close(handle)
print(f'PASS: actual libdtrace parser survives {failures} allocation-failure positions with no tracked DIF/statement/program leaks, then parses and destroys successfully')
