# Phase 1: hwstat on the real AMD host.
# RAPL package energy via cpuctl (cross-checked against raw MSRs read with
# cpucontrol), per-core data, amdtemp/ACPI temperatures, `hwstat exec`
# energy of a known workload, OTLP export validated by the independent
# validators, and the coverage-instrumented run.

phase_begin hwstat
need_root
HT_ALLOW_GENERATION=${HT_ALLOW_GENERATION:-$(host_generation)}  # hwstat needs no vmm
need_generation
need_cpuctl
need_tool cpucontrol
[ -x "$HT_KIT/bin/otlp_collector" ] && [ -x "$HT_KIT/bin/otlp_validate" ] ||
    refuse "kit OTLP tools missing under $HT_KIT/bin"
dry && dry_end

O=$HT_OUT
H=/usr/sbin/hwstat
ncpu=$(sysctl -n hw.ncpu)

# 1. CPU identity (CPUID leaf 1 via cpuctl).
cpucontrol -i 1 /dev/cpuctl0 > "$O/cpuid1.txt" 2>&1
eax=$(awk '{print $4}' "$O/cpuid1.txt" | head -1)
fam=$(( ((eax >> 8) & 0xf) + ((eax >> 20) & 0xff) ))
model=$(( ((eax >> 4) & 0xf) | (((eax >> 16) & 0xf) << 4) ))
printf 'family=0x%x model=0x%x hw.model=%s\n' "$fam" "$model" "$(sysctl -n hw.model)" | tee "$O/cpu.txt" >> "$HT_LOG"
case $fam in 23|25|26) check cpu-amd-rapl-family PASS "$(cat "$O/cpu.txt")" ;;
*) check cpu-amd-rapl-family FAIL "family $fam not in 0x17/0x19/0x1a" ;; esac

# 2. hwstat list (JSON).
$H list --format json > "$O/list.json" 2> "$O/list.err"
if grep -q '"rapl_available":true' "$O/list.json"; then
	check list-rapl-available PASS "$(grep -o '"rapl_domains":[^]]*]' "$O/list.json")"
else
	check list-rapl-available FAIL "rapl_available is not true (see list.json)"
fi
grep -q '"package"' "$O/list.json" && check list-package-domain PASS ||
    check list-package-domain FAIL "no package domain"

# 3. Raw MSR cross-check (independent of hwstat): energy unit + package
#    energy status sampled 2 s apart.
# cpucontrol prints "MSR 0x...: 0xHIGH 0xLOW"; awk cannot read hex, so
# let the shell convert the low 32 bits.
msr() { v=$(cpucontrol -m "$1" /dev/cpuctl0 | awk '{print $4}'); echo $((v)); }
unit=$(msr 0xc0010299); esu=$(( (unit >> 8) & 0x1f ))
e0=$(msr 0xc001029b); t0=$(date +%s); sleep 2; e1=$(msr 0xc001029b); t1=$(date +%s)
d=$(( (e1 - e0) & 0xffffffff ))
msr_watts=$(echo "scale=3; $d / (2^$esu) / ($t1 - $t0)" | bc)
echo "esu=$esu e0=$e0 e1=$e1 delta=$d seconds=$((t1 - t0)) watts=$msr_watts" > "$O/msr-crosscheck.txt"
if [ "$d" -gt 0 ]; then check msr-package-energy-advances PASS "$msr_watts W from raw MSR"; else
	check msr-package-energy-advances FAIL "MSR 0xc001029b did not advance"; fi

# 4. watch: package power, temperatures, frequency.
$H watch --interval 1 --duration 3 --format json > "$O/watch.json" 2> "$O/watch.err"
pw=$(sed -n 's/.*"package_watts":\([0-9.]*\).*/\1/p' "$O/watch.json" | tail -1)
if [ -n "$pw" ] && [ "$(echo "$pw > 0.5 && $pw < 200" | bc)" = 1 ]; then
	check watch-package-watts PASS "$pw W (raw MSR $msr_watts W)"
else
	check watch-package-watts FAIL "package_watts='$pw'"
fi
# hwstat vs raw MSR within a factor of 3 (load fluctuates between samples).
if [ -n "$pw" ] && [ "$(echo "$pw < $msr_watts * 3 + 5 && $pw * 3 + 5 > $msr_watts" | bc)" = 1 ]; then
	check watch-matches-msr PASS "hwstat $pw W vs MSR $msr_watts W"
else
	check watch-matches-msr FAIL "hwstat '$pw' W vs MSR $msr_watts W"
fi
sysctl dev.amdtemp hw.acpi.thermal > "$O/thermal-sysctl.txt" 2>&1
if grep -q 'dev.amdtemp' "$O/watch.json"; then
	t=$(sed -n 's/.*"source":"dev.amdtemp[^"]*","celsius":\([0-9.]*\).*/\1/p' "$O/watch.json" | tail -1)
	if [ -n "$t" ] && [ "$(echo "$t > 15 && $t < 110" | bc)" = 1 ]; then
		check temperature-amdtemp PASS "$t C"
	else check temperature-amdtemp FAIL "amdtemp value '$t'"; fi
elif grep -q '^dev.amdtemp' "$O/thermal-sysctl.txt"; then
	check temperature-amdtemp FAIL "dev.amdtemp present but not reported by hwstat"
else
	check temperature-amdtemp SKIP "amdtemp not attached (kldload amdtemp is not done by this kit)"
fi
grep -q 'hw.acpi.thermal.tz0.temperature' "$O/thermal-sysctl.txt" &&
    { grep -q '"acpi_temp"' "$O/list.json" && check temperature-acpi PASS || check temperature-acpi FAIL "tz0 exists but acpi_temp missing"; } ||
    check temperature-acpi SKIP "no ACPI thermal zone"
f=$(sed -n 's/.*"freq_max_mhz":\([0-9]*\).*/\1/p' "$O/watch.json" | tail -1)
[ -n "$f" ] && [ "$f" -gt 0 ] && check cpu-frequency PASS "max $f MHz" || check cpu-frequency FAIL "freq_max_mhz='$f'"
grep -o '"metric_sources":[^]]*]' "$O/watch.json" | tail -1 > "$O/gpu-metric-sources.txt"
check gpu-metric-sources PASS "info: $(cat "$O/gpu-metric-sources.txt" | cut -c1-200)"

# 5. Per-core data.
$H watch --interval 1 --duration 2 --per-core --format json > "$O/watch-percore.json" 2>&1
n=$(tail -1 "$O/watch-percore.json" | grep -o '"cpu":[0-9]*' | sort -u | wc -l | tr -d ' ')
[ "$n" -eq "$ncpu" ] && check percore-all-cpus PASS "$n of $ncpu" || check percore-all-cpus FAIL "$n of $ncpu cores reported"
grep -q '"cpu_usage_pct"' "$O/watch-percore.json" && check percore-usage PASS || check percore-usage FAIL

# 6. hwstat exec: energy of a known workload (all threads busy 5 s) vs idle 5 s.
busy="i=1; while [ \$i -le $ncpu ]; do timeout 5 sh -c 'while :; do :; done' & i=\$((i+1)); done; wait; exit 0"
$H exec --format json -- /bin/sleep 5 > "$O/exec-idle.json" 2> "$O/exec-idle.err"
$H exec --format json --per-core -- /bin/sh -c "$busy" > "$O/exec-busy.json" 2> "$O/exec-busy.err"
ji=$(sed -n 's/.*"package":{"joules":\([0-9.]*\).*/\1/p' "$O/exec-idle.json")
jb=$(sed -n 's/.*"package":{"joules":\([0-9.]*\).*/\1/p' "$O/exec-busy.json")
wb=$(sed -n 's/.*"package":{"joules":[0-9.]*,"watts":\([0-9.]*\).*/\1/p' "$O/exec-busy.json")
grep -q '"energy_status":"available"' "$O/exec-busy.json" && check exec-energy-available PASS ||
    check exec-energy-available FAIL "$(grep -o '"energy_status":"[^"]*"' "$O/exec-busy.json")"
if [ -n "$ji" ] && [ -n "$jb" ] && [ "$(echo "$jb > $ji" | bc)" = 1 ]; then
	check exec-busy-exceeds-idle PASS "busy ${jb} J (${wb} W) > idle ${ji} J over 5 s"
else
	check exec-busy-exceeds-idle FAIL "busy '$jb' J vs idle '$ji' J (host load from other jobs can mask this; rerun when idle)"
fi
$H exec --format json -- /bin/sh -c 'exit 7' > "$O/exec-exit.json" 2>&1; rc=$?
[ $rc -eq 7 ] && check exec-exit-propagates PASS || check exec-exit-propagates FAIL "exit $rc"
$H exec -- /bin/sleep 1 > "$O/exec-text.out" 2> "$O/exec-text.err"
grep -q 'Total package energy:' "$O/exec-text.out" && check exec-text-total PASS || check exec-text-total FAIL

# 7. OTLP export to the loopback collector (http/json), independent validators.
mkdir -p "$O/otlp"
"$HT_KIT/bin/otlp_collector" -o "$O/otlp" -p 0 -t 60 > "$O/otlp-collector.log" 2>&1 &
cpid=$!; at_cleanup "kill $cpid 2>/dev/null"
i=0; while [ ! -s "$O/otlp/port" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
printf 'protocol = "http/json";\nendpoint = "http://127.0.0.1:%s";\n' "$(cat "$O/otlp/port")" > "$O/otel-http.conf"
OTELCONF_FILE=$O/otel-http.conf $H watch --format otel --interval 1 --duration 4 --per-core > "$O/otel-watch.log" 2>&1
sleep 1; kill $cpid 2>/dev/null; wait $cpid 2>/dev/null
if ls "$O"/otlp/*.json >/dev/null 2>&1 && "$HT_KIT/bin/otlp_validate" "$O"/otlp/*.json > "$O/otlp-validate.txt" 2>&1; then
	check otlp-validate PASS "$(cat "$O/otlp-validate.txt")"
else
	check otlp-validate FAIL "$(cat "$O/otlp-validate.txt" 2>/dev/null | tail -1)"
fi
for f in "$O"/otlp/*.json; do "$HT_KIT/bin/otlp_json_validate" "$f"; done > "$O/otlp-points.txt" 2>&1
for m in hwstat.power.package_milliwatts hwstat.thermal.temperature_millicelsius hwstat.cpu.freq_mhz hwstat.cpu.busy_basis_points; do  # --per-core exports busy per CPU
	if grep -E "^point $m( |$)" "$O/otlp-points.txt" | grep -q .; then
		check "otlp-metric-$m" PASS "$(grep -E "^point $m" "$O/otlp-points.txt" | tail -1 | cut -c1-160)"
	else
		check "otlp-metric-$m" FAIL "not exported"
	fi
done
pmw=$(grep -E '^point hwstat.power.package_milliwatts' "$O/otlp-points.txt" | tail -1 | awk '{print $NF}')
[ -n "$pmw" ] && [ "$(echo "$pmw > 500" | bc)" = 1 ] && check otlp-package-power-nonzero PASS "$pmw mW" ||
    check otlp-package-power-nonzero FAIL "package_milliwatts '$pmw'"
# File target.
mkdir -p "$O/otel-file"
printf 'export { target = "file"; directory = "%s"; }\n' "$O/otel-file" > "$O/otel-file.conf"
OTELCONF_FILE=$O/otel-file.conf $H watch --format otel --interval 1 --duration 2 > "$O/otel-file.log" 2>&1
"$HT_KIT/bin/otlp_validate" "$O/otel-file/hwstat.jsonl" > "$O/otel-file-validate.txt" 2>&1 &&
    grep -q 'hwstat.power.package_milliwatts' "$O/otel-file/hwstat.jsonl" &&
    check otlp-file-target PASS "$(cat "$O/otel-file-validate.txt")" ||
    check otlp-file-target FAIL "see otel-file-validate.txt"

# 8. Coverage-instrumented run (hardware paths).
if [ -x "$HT_KIT/coverage/hwstat/bin/hwstat" ]; then
	"$HT_KIT/coverage/run-hwstat-cov.sh" "$O/coverage" > "$O/coverage.log" 2>&1
	cov=$(cat "$O/coverage/coverage.summary" 2>/dev/null)
	rl=$(awk '$1 == "rapl.c" {print $10}' "$O/coverage/report-hwstat-hw-only.txt" 2>/dev/null)
	if [ -n "$rl" ] && [ "$(echo "${rl%\%} > 50" | bc)" = 1 ]; then
		check coverage-rapl-hardware-path PASS "rapl.c lines $rl from real-hardware runs only"
	else
		check coverage-rapl-hardware-path FAIL "rapl.c hardware-only line coverage '$rl'"
	fi
	grep -q 'noresult\|failed' "$O/coverage.log" &&
	    check coverage-suite FAIL "some unit/CLI cases failed (coverage.log)" ||
	    check coverage-suite PASS "combined $cov (baseline 78.85%/65.60%)"
else
	check coverage-suite SKIP "instrumented hwstat not built (coverage/build-hwstat-cov.sh)"
fi
phase_end
