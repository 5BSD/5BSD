#!/bin/sh
# Run the coverage-instrumented hwstat: unit tests, the atf CLI suite and the
# real-hardware invocations, then merge and report.
#   usage: run-hwstat-cov.sh OUTDIR
# As root on the AMD host this reaches the RAPL/cpuctl, amdtemp and per-core
# paths that the recorded 78.85%/65.60% (lines/branches) baseline could not.
# Unprivileged it still runs (useful as a dry run), without the RAPL paths.
set -u
KIT=$(cd "$(dirname "$0")/.." && pwd)
C=$KIT/coverage/hwstat
OUT=${1:?OUTDIR}
mkdir -p "$OUT/raw" "$OUT/atf"
B=$C/bin
[ -x "$B/hwstat" ] || { echo "instrumented hwstat missing: run coverage/build-hwstat-cov.sh" >&2; exit 2; }
export PATH="$B:/sbin:/bin:/usr/sbin:/usr/bin"
export HWSTAT=$B/hwstat
fail=0
prof() { echo "$OUT/raw/$1-%p.profraw"; }

# 1. atf-c unit tests (every case of every program).
for t in sensors_test metrics_test sampling_test exec_timing_test rapl_test; do
	for tc in $("$B/$t" -l | sed -n 's/^ident: //p'); do
		( cd "$OUT/atf" && LLVM_PROFILE_FILE=$(prof "$t-$tc") \
		    timeout 300 "$B/$t" -s "$B" -r "$OUT/atf/$t.$tc.result" "$tc" ) \
		    > "$OUT/atf/$t.$tc.log" 2>&1
		r=$(head -1 "$OUT/atf/$t.$tc.result" 2>/dev/null)
		echo "unit $t:$tc ${r:-noresult}"
		case "$r" in passed*|skipped*|expected_*) ;; *) fail=1 ;; esac
	done
done
# 2. atf-sh CLI suite against the instrumented binary.
for tc in $(/usr/libexec/atf-sh "$C/src/hwstat_test.sh" -l | sed -n 's/^ident: //p'); do
	( cd "$OUT/atf" && LLVM_PROFILE_FILE=$(prof "cli-$tc") \
	    timeout 300 /usr/libexec/atf-sh "$C/src/hwstat_test.sh" -s "$C/src" -r "$OUT/atf/cli.$tc.result" "$tc" ) \
	    > "$OUT/atf/cli.$tc.log" 2>&1
	r=$(head -1 "$OUT/atf/cli.$tc.result" 2>/dev/null)
	echo "cli $tc ${r:-noresult}"
	case "$r" in passed*|skipped*|expected_*) ;; *) fail=1 ;; esac
done
# 3. Real-hardware invocations (these are the point of the exercise).
hw() {
	name=$1; shift
	LLVM_PROFILE_FILE=$(prof "hw-$name") timeout 120 "$B/hwstat" "$@" \
	    > "$OUT/hw-$name.out" 2> "$OUT/hw-$name.err"
	echo "hw $name exit=$?"
}
hw list-text list
hw list-json list --format json
hw list-percore list --per-core --format json
hw watch-json watch --interval 0.5 --duration 2 --format json
hw watch-percore watch --interval 0.5 --duration 2 --per-core --format json
hw watch-text watch --interval 1 --duration 2
hw exec-json exec --format json -- /bin/sh -c 'i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done'
hw exec-percore exec --per-core --format json -- /bin/sh -c 'i=0; while [ $i -lt 100000 ]; do i=$((i+1)); done'
hw exec-text exec -- /bin/sleep 1
hw exec-fail exec --format json -- /bin/sh -c 'exit 3'
hw tiny-interval watch --interval 0.001 --duration 0.05 --format json
# OTLP: file target, then loopback collector.
mkdir -p "$OUT/otel-file"
printf 'export { target = "file"; directory = "%s"; }\n' "$OUT/otel-file" > "$OUT/otel-file.conf"
OTELCONF_FILE=$OUT/otel-file.conf hw otel-file watch --format otel --interval 0.5 --duration 2 --per-core
mkdir -p "$OUT/otel-collector"
"$KIT/bin/otlp_collector" -o "$OUT/otel-collector" -p 0 -t 30 &
cpid=$!
i=0; while [ ! -s "$OUT/otel-collector/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
printf 'protocol = "http/json";\nendpoint = "http://127.0.0.1:%s";\n' "$(cat "$OUT/otel-collector/port")" > "$OUT/otel-http.conf"
OTELCONF_FILE=$OUT/otel-http.conf hw otel-http watch --format otel --interval 0.5 --duration 2
kill "$cpid" 2>/dev/null; wait "$cpid" 2>/dev/null

# 4. Merge and report.
cd "$C/src" || exit 2
llvm-profdata merge -sparse "$OUT"/raw/*.profraw -o "$OUT/hwstat.profdata" || exit 2
objs=""
for t in sensors_test metrics_test sampling_test exec_timing_test rapl_test; do objs="$objs -object $B/$t"; done
llvm-cov report "$B/hwstat" $objs -instr-profile="$OUT/hwstat.profdata" \
    -ignore-filename-regex="(tests/|libotelexport|contrib/)" > "$OUT/report-hwstat.txt" 2>&1
llvm-cov show "$B/hwstat" $objs -instr-profile="$OUT/hwstat.profdata" \
    -show-branches=count -ignore-filename-regex="(tests/|libotelexport|contrib/)" > "$OUT/show-hwstat.txt" 2>&1
# Hardware-only view: only the real-hardware invocations.
llvm-profdata merge -sparse "$OUT"/raw/hw-*.profraw -o "$OUT/hw-only.profdata" &&
    llvm-cov report "$B/hwstat" -instr-profile="$OUT/hw-only.profdata" \
    -ignore-filename-regex="(tests/|libotelexport|contrib/)" > "$OUT/report-hwstat-hw-only.txt" 2>&1
tot=$(awk '$1 == "TOTAL" {print "lines=" $10 " branches=" $13}' "$OUT/report-hwstat.txt")
echo "COVERAGE hwstat $tot (baseline lines=78.85% branches=65.60%)"
echo "$tot" > "$OUT/coverage.summary"
exit $fail
