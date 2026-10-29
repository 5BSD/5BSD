#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The out-of-the-box emitters that reuse existing tools: hwstat(8) and
# bsdinstruments(8) take their OTLP settings from otel.conf(5).  Checked
# with the local fake OTLP receiver and the OTLP-JSON validator.
#

: ${HWSTAT:=/usr/sbin/hwstat}
: ${BSDINSTRUMENTS:=/usr/sbin/bsdinstruments}
: ${OTEL_HELPERS:=$(atf_get_srcdir)}
VALIDATE="${OTEL_HELPERS}/otlp_json_validate"

receiver_start()
{
	mkdir -p out
	"${OTEL_HELPERS}/otlp_fake_receiver" -p port -d out "$@" &
	echo $! > receiver.pid
	i=0
	while [ ! -s port ] && [ $i -lt 100 ]; do
		sleep 0.05
		i=$((i + 1))
	done
	[ -s port ] || atf_fail "fake receiver did not start"
	PORT=$(cat port)
}

receiver_wait()
{
	wait "$(cat receiver.pid)" || atf_fail "fake receiver failed"
}

config()
{
	printf 'Authorization: Bearer from-otel-conf\n' > creds
	chmod 0600 creds
	cat > otel.conf <<EOF
endpoint = "http://127.0.0.1:${PORT:-9}";
headers_file = "$(pwd)/creds";
host_id_file = "$(pwd)/hostid";
resource {
	"service.namespace" = "emitters";
	"deployment.environment.name" = "ci";
}
$1
EOF
	echo "11111111-2222-3333-4444-555555555555" > hostid
	OTELCONF_DEFAULTS=/nonexistent/otel.conf
	OTELCONF_FILE="$(pwd)/otel.conf"
	export OTELCONF_DEFAULTS OTELCONF_FILE
}

atf_test_case hwstat_system_config
hwstat_system_config_head()
{
	atf_set "descr" "hwstat --format otel uses the otel.conf settings"
}
hwstat_system_config_body()
{
	[ -x "${HWSTAT}" ] || atf_skip "hwstat is not installed"
	receiver_start -n 1 -t 30
	config
	atf_check -e ignore "${HWSTAT}" watch --format otel --interval 0.5 \
	    --duration 1.2
	receiver_wait
	atf_check -o match:"^POST /v1/metrics" \
	    -o match:"^Authorization: Bearer from-otel-conf" cat out/0000.hdr
	atf_check -o match:"^resource service.name=hwstat$" \
	    -o match:"^resource service.namespace=emitters$" \
	    -o match:"^resource deployment.environment.name=ci$" \
	    -o match:"^resource host.id=11111111-2222-3333-4444-555555555555$" \
	    -o match:"^metric hwstat\." \
	    ${VALIDATE} out/0000.json
}

atf_test_case hwstat_precedence
hwstat_precedence_head()
{
	atf_set "descr" "hwstat: environment beats otel.conf, --endpoint both"
}
hwstat_precedence_body()
{
	[ -x "${HWSTAT}" ] || atf_skip "hwstat is not installed"
	receiver_start -n 1 -t 30
	REAL=$PORT
	PORT=9 config
	# The environment names the real receiver: no otel.conf credentials.
	atf_check -e ignore env \
	    OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:${REAL}" \
	    OTEL_RESOURCE_ATTRIBUTES="deployment.environment.name=env" \
	    "${HWSTAT}" watch --format otel --interval 0.5 --duration 0.6
	receiver_wait
	atf_check -s exit:1 grep -qi "^Authorization" out/0000.hdr
	atf_check -o match:"^resource deployment.environment.name=env$" \
	    -o match:"^resource service.namespace=emitters$" \
	    ${VALIDATE} out/0000.json

	rm -f port out/*
	receiver_start -n 1 -t 30
	atf_check -e ignore env \
	    OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:9" \
	    "${HWSTAT}" watch --format otel --interval 0.5 --duration 0.6 \
	    --endpoint "http://127.0.0.1:${PORT}"
	receiver_wait
	atf_check -o match:"^resource service.name=hwstat$" \
	    ${VALIDATE} out/0000.json
}

atf_test_case hwstat_bad_config
hwstat_bad_config_head()
{
	atf_set "descr" "hwstat refuses OTLP export with a broken otel.conf"
}
hwstat_bad_config_body()
{
	[ -x "${HWSTAT}" ] || atf_skip "hwstat is not installed"
	config
	chmod 0644 creds
	atf_check -s not-exit:0 -e match:"creds: mode 0644" \
	    "${HWSTAT}" watch --format otel --interval 0.5 --duration 0.6
	# Text output does not involve the exporter configuration.
	atf_check -o ignore -e ignore "${HWSTAT}" watch --interval 0.5 \
	    --duration 0.6
}

atf_test_case dtrace_bad_config
dtrace_bad_config_head()
{
	atf_set "descr" "bsdinstruments refuses OTLP export with a broken otel.conf"
}
dtrace_bad_config_body()
{
	[ -x "${BSDINSTRUMENTS}" ] || atf_skip "bsdinstruments is not installed"
	config 'timeout_ms = 0;'
	atf_check -s exit:1 -e match:"timeout_ms 0 is outside" \
	    "${BSDINSTRUMENTS}" watch system-metrics --format otel \
	    --duration 1
}

atf_test_case dtrace_profile_renders
dtrace_profile_renders_head()
{
	atf_set "descr" "The system-metrics profile is installed and renders"
}
dtrace_profile_renders_body()
{
	[ -x "${BSDINSTRUMENTS}" ] || atf_skip "bsdinstruments is not installed"
	atf_check -o match:"io:::done" -o match:"proc:::exit" \
	    -o not-match:"syscall::" -o not-match:"fbt::" \
	    -o not-match:"sched:::" -o not-match:"profile-" \
	    "${BSDINSTRUMENTS}" generate system-metrics
}

atf_test_case dtrace_system_metrics
dtrace_system_metrics_head()
{
	atf_set "descr" "system-metrics exports DTrace aggregations as OTLP"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
dtrace_system_metrics_body()
{
	[ -x "${BSDINSTRUMENTS}" ] || atf_skip "bsdinstruments is not installed"
	kldstat -q -m dtrace || atf_skip "DTrace is not loaded"
	receiver_start -n 1 -t 60
	config
	"${BSDINSTRUMENTS}" watch system-metrics --format otel --duration 4 \
	    > bi.out 2>&1 &
	pid=$!
	sleep 1
	# Process churn, a signal and some disk I/O inside the window.
	for i in 1 2 3 4 5; do /usr/bin/true; done
	sh -c 'kill -USR1 $$' || true
	dd if=/dev/zero of=io.tmp bs=64k count=64 2>/dev/null
	sync
	wait $pid || { cat bi.out; atf_fail "bsdinstruments failed"; }
	receiver_wait
	atf_check -o match:"^Authorization: Bearer from-otel-conf" \
	    cat out/0000.hdr
	atf_check -o save:summary ${VALIDATE} out/0000.json
	atf_check -o match:"^resource service.namespace=emitters$" \
	    -o match:"^metric bsdinstruments.system-metrics.exec sum monotonic=1$" \
	    -o match:"^metric bsdinstruments.system-metrics.exits sum" \
	    -o match:"^point bsdinstruments.system-metrics.signals \[signal=" \
	    cat summary
}

atf_init_test_cases()
{
	atf_add_test_case hwstat_system_config
	atf_add_test_case hwstat_precedence
	atf_add_test_case hwstat_bad_config
	atf_add_test_case dtrace_bad_config
	atf_add_test_case dtrace_profile_renders
	atf_add_test_case dtrace_system_metrics
}
