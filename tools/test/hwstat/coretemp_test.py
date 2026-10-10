#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compile actual coretemp handlers with instrumented register access."""
from pathlib import Path
import subprocess
import tempfile

src = (Path(__file__).resolve().parents[3] / 'sys/dev/coretemp/coretemp.c').read_text()
constants = src[src.index('#define\tTZ_ZEROC'):src.index('struct coretemp_softc')]
status = src[src.index('static int\ncoretemp_thermal_status_sysctl('):
             src.index('static void\ncoretemp_clear_thermal_msr(')]
value = src[src.index('static int\ncoretemp_get_val_sysctl('):
            src.index('static int\ncoretemp_throttle_log_sysctl(')]
preamble = r'''
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
typedef void *device_t;
struct coretemp_softc { int sc_tjmax; unsigned sc_throttle_log; } sc = {100, 0};
struct sysctl_oid { int unused; };
struct sysctl_req { void *newptr; int output; };
#define SYSCTL_HANDLER_ARGS struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req
enum therm_info { CORETEMP_TEMP, CORETEMP_DELTA, CORETEMP_RESOLUTION, CORETEMP_TJMAX };
static int reads, clears;
static uint64_t msr;
static int device_get_unit(device_t dev) { return 0; }
static struct coretemp_softc *device_get_softc(device_t dev) { return &sc; }
static uint64_t coretemp_get_thermal_msr(int cpu) { reads++; return msr; }
static void coretemp_clear_thermal_msr(int cpu) { clears++; msr = 0; }
static int sysctl_handle_int(struct sysctl_oid *o, void *v, int x, struct sysctl_req *r) {
    memcpy(&r->output, v, sizeof(r->output)); return 0;
}
#define device_printf(...) ((void)0)
#define devctl_notify(...) ((void)0)
'''
tests = r'''
int main(void) {
    struct sysctl_oid oid = {0};
    struct sysctl_req req = {0};
    msr = (1ULL << 31) | (25ULL << 16) | 3;
    assert(coretemp_thermal_status_sysctl(&oid, &sc, 0, &req) == 0);
    assert((uint32_t)req.output == (uint32_t)msr);
    assert(reads == 1 && clears == 0);
    assert(coretemp_get_val_sysctl(&oid, &sc, CORETEMP_TJMAX, &req) == 0);
    assert(req.output == 3731 && reads == 1 && clears == 0);
    req.newptr = &sc;
    assert(coretemp_thermal_status_sysctl(&oid, &sc, 0, &req) == EPERM);
    assert(reads == 1 && clears == 0);
    req.newptr = NULL;
    assert(coretemp_get_val_sysctl(&oid, &sc, CORETEMP_TEMP, &req) == 0);
    assert(req.output == 3481 && clears == 1 && sc.sc_throttle_log == 1);
    assert(coretemp_get_val_sysctl(&oid, &sc, CORETEMP_TJMAX, &req) == 0);
    assert(req.output == 3731 && reads == 2 && clears == 1);
    puts("coretemp: raw status/Tjmax preserve logs, writes rejected, legacy behavior retained");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='hwstat-coretemp-') as directory:
    source = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    source.write_text(preamble + constants + status + value + tests)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Werror',
                    '-o', str(binary), str(source)], check=True)
    subprocess.run([str(binary)], check=True)
