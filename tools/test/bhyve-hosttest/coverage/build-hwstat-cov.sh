#!/bin/sh
# Build a coverage-instrumented hwstat (clang source-based coverage) for the
# real-hardware run in phase "hwstat". Run as an ordinary user, before or
# after upgrading; rebuild after upgrading if /usr/src moved.
#   usage: build-hwstat-cov.sh [OUTDIR]
#   env:   SRC=/usr/src  OTELEXPORT_A=<objdir>/lib/libotelexport/libotelexport_pie.a
# Only hwstat's own sources (main rapl sensors metrics format) are
# instrumented: these are the files in the recorded 78.85%/65.60% report
# (merge2-cov/vm-report-hwstat.txt). libotelexport is linked uninstrumented
# from the world object tree, the same way hwstat links it statically.
set -eu
KIT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$KIT/coverage/hwstat}
SRC=${SRC:-/usr/src}
OBJ=${OBJ:-/usr/obj$SRC/amd64.amd64}
A=${OTELEXPORT_A:-$OBJ/lib/libotelexport/libotelexport_pie.a}
UPB=${UPB_A:-$OBJ/lib/protobuf/libupb/libupb_pie.a}
[ "$(id -u)" -ne 0 ] || echo "note: running as root is not needed for this build" >&2
for f in "$A" "$UPB"; do [ -f "$f" ] || { echo "missing $f (build world first)" >&2; exit 1; }; done
H=$SRC/usr.sbin/hwstat
rm -rf "$OUT"; mkdir -p "$OUT/obj" "$OUT/bin" "$OUT/src"
CF="-O0 -g -fPIE -fprofile-instr-generate -fcoverage-mapping -I$H -I$SRC/lib/libotelexport -std=gnu17 -Wall -Wno-unused-parameter"
objs=
for s in main rapl sensors metrics format; do
	cc $CF -c "$H/$s.c" -o "$OUT/obj/$s.o"
	objs="$objs $OUT/obj/$s.o"
done
cc -pie -fprofile-instr-generate -o "$OUT/bin/hwstat" $objs "$A" "$UPB" \
    -lprivateucl -lprivatenghttp2 -lssl -lcrypto -lz -lthr -lm
# Instrumented unit tests, linked as tests/Makefile does (the recorded
# baseline included them; rapl_test mocks the MSRs).
LIBS="$A $UPB -lprivateucl -lprivatenghttp2 -lssl -lcrypto -lz -lthr -lm"
hobj="$OUT/obj/rapl.o $OUT/obj/sensors.o $OUT/obj/metrics.o $OUT/obj/format.o"
for t in sensors_test metrics_test sampling_test exec_timing_test rapl_test; do
	cc $CF -c "$H/tests/$t.c" -o "$OUT/obj/$t.o"
	case $t in
	sensors_test) deps="$OUT/obj/metrics.o" ;;
	metrics_test|rapl_test) deps="" ;;
	*) deps="$hobj" ;;
	esac
	cc -pie -fprofile-instr-generate -o "$OUT/bin/$t" "$OUT/obj/$t.o" $deps \
	    -lprivateatf-c $LIBS
done
# Sources and the CLI test script, so the report can be produced later even
# if /usr/src moves on.
for s in main rapl sensors metrics format; do cp "$H/$s.c" "$OUT/src/"; done
cp "$H/hwstat.h" "$OUT/src/"; cp "$H/tests/hwstat_test.sh" "$OUT/src/"
{
	echo "src=$SRC"
	echo "revision=$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
	echo "hwstat_last_change=$(git -C "$SRC" log -1 --format=%H -- usr.sbin/hwstat lib/libotelexport 2>/dev/null || echo unknown)"
	echo "otelexport_archive=$A $(sha256 -q "$A")"; echo "upb_archive=$UPB $(sha256 -q "$UPB")"
	echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ) by uid $(id -u)"
	echo "binary_sha256=$(sha256 -q "$OUT/bin/hwstat")"
} > "$OUT/BUILDINFO"
# Smoke: the instrumented binary must run unprivileged and write a profile.
LLVM_PROFILE_FILE="$OUT/smoke-%p.profraw" "$OUT/bin/hwstat" list --format json > "$OUT/smoke.json"
grep -q '"logical_cpus"' "$OUT/smoke.json"
ls "$OUT"/smoke-*.profraw >/dev/null
rm -f "$OUT"/smoke-*.profraw
echo "built $OUT/bin/hwstat"; cat "$OUT/BUILDINFO"
