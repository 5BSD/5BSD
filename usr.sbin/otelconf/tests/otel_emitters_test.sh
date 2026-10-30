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
spool { directory = "$(pwd)/spool"; }
$1
EOF
	mkdir -p spool
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

atf_test_case hwstat_system_spool
hwstat_system_spool_head()
{
	atf_set "descr" "hwstat spools to the otel.conf spool directory and resends"
	atf_set "timeout" "120"
}
hwstat_system_spool_body()
{
	[ -x "${HWSTAT}" ] || atf_skip "hwstat is not installed"
	# Port 9 on loopback refuses: the batches go to spool/hwstat.spool.
	PORT=9 config
	atf_check -o ignore -e match:"spooled /v1/metrics batch to .*/spool/hwstat.spool" \
	    "${HWSTAT}" watch --format otel --interval 0.5 --duration 1.2
	atf_check test -s spool/hwstat.spool
	atf_check test -f spool/hwstat.spool.lock
	# The collector is back: the next run resends, oldest first.
	receiver_start -n 0 -t 8
	config
	atf_check -o ignore -e match:"resent [0-9]+ spooled batch" \
	    "${HWSTAT}" watch --format otel --interval 0.5 --duration 1.2
	receiver_wait
	atf_check -o empty cat spool/hwstat.spool
	atf_check -o match:"^metric hwstat\." ${VALIDATE} out/0000.json
	# A spool directory this user cannot write: no spool, no error.
	chmod 0500 spool
	if [ ! -w spool ]; then
		rm -f port out/*
		receiver_start -n 1 -t 30
		config
		atf_check -o ignore -e not-match:"spool" "${HWSTAT}" watch \
		    --format otel --interval 0.5 --duration 0.6
		receiver_wait
	fi
	chmod 0700 spool
}

atf_test_case hwstat_percore
hwstat_percore_head()
{
	atf_set "descr" "hwstat --per-core exports per-CPU points with cpu.logical_number"
}
hwstat_percore_body()
{
	[ -x "${HWSTAT}" ] || atf_skip "hwstat is not installed"
	receiver_start -n 1 -t 30
	config
	atf_check -o ignore -e ignore "${HWSTAT}" watch --format otel \
	    --per-core --interval 0.5 --duration 1.2
	receiver_wait
	atf_check -o match:"^point hwstat\.cpu\.[a-z_]+ \[cpu.logical_number=0\]" \
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
	    -o match:"tcp:::state-change" \
	    -o match:"this->network__connection__state" \
	    -o not-match:"syscall::" -o not-match:"fbt::" \
	    -o not-match:"sched:::" -o not-match:"profile-" \
	    "${BSDINSTRUMENTS}" generate system-metrics
}

atf_test_case dtrace_system_metrics
dtrace_system_metrics_head()
{
	atf_set "descr" "system-metrics exports DTrace aggregations as OTLP"
	atf_set "require.user" "root"
	atf_set "timeout" "300"
}
dtrace_system_metrics_body()
{
	[ -x "${BSDINSTRUMENTS}" ] || atf_skip "bsdinstruments is not installed"
	kldstat -q -m dtrace || atf_skip "DTrace is not loaded"
	# Any number of requests: the metrics, and log records of runtime
	# errors (dtrace.error) when a probe faults.
	receiver_start -n 0 -t 300
	config
	"${BSDINSTRUMENTS}" watch system-metrics --format otel --duration 15 \
	    > bi.out 2>&1 &
	pid=$!
	# Process churn, a signal and disk I/O for the whole window: the
	# profile may take a while to compile on a slow (emulated) host.
	tmp=$(mktemp /var/tmp/otel-io.XXXXXX)
	nc=$(command -v nc) || nc=
	port=$((20000 + $$ % 20000))
	while kill -0 $pid 2>/dev/null; do
		/usr/bin/true
		sh -c 'kill -USR1 $$' 2>/dev/null || true
		# conv=fsync: the writes complete (io:::done) before dd
		# returns; /var/tmp is a disk file system, unlike a tmpfs
		# work directory.
		dd if=/dev/zero of="$tmp" bs=64k count=16 conv=fsync 2>/dev/null
		# A loopback TCP connection: listen, established and, for
		# the closing side, time_wait (tcp:::state-change).
		if [ -n "$nc" ]; then
			port=$((port + 1))
			$nc -l 127.0.0.1 $port > /dev/null 2>&1 &
			lpid=$!
			sleep 0.3
			echo x | $nc -N 127.0.0.1 $port > /dev/null 2>&1
			sleep 0.3
			kill $lpid 2>/dev/null
			wait $lpid 2>/dev/null
		fi
		sleep 1
	done
	rm -f "$tmp"
	wait $pid || { cat bi.out; atf_fail "bsdinstruments failed"; }
	sleep 2
	kill "$(cat receiver.pid)" 2>/dev/null
	wait "$(cat receiver.pid)" 2>/dev/null
	atf_check -o match:"^Authorization: Bearer from-otel-conf" \
	    cat out/0000.hdr
	: > summary
	for f in out/*.json; do
		atf_check -o save:one ${VALIDATE} "$f"
		cat one >> summary
	done
	atf_check -o match:"^resource service.namespace=emitters$" \
	    -o match:"^metric bsdinstruments.system-metrics.exec sum monotonic=1$" \
	    -o match:"^metric bsdinstruments.system-metrics.exits sum" \
	    -o match:"^point bsdinstruments.system-metrics.signals \[signal=" \
	    -o match:"^point bsdinstruments.system-metrics.io_bytes \[system.device=[a-z]+[0-9]+,disk.io.direction=(read|write)\] [1-9]" \
	    cat summary
	[ -n "$nc" ] || return 0
	atf_check -o match:"^point bsdinstruments.system-metrics.tcp_state_changes \[network.connection.state=established\] [1-9]" \
	    -o match:"^point bsdinstruments.system-metrics.tcp_state_changes \[network.connection.state=time_wait\] [1-9]" \
	    -o not-match:"network.connection.state=state-" \
	    cat summary
}

# Validate every line of an OTLP JSON Lines file on its own.
validate_lines()
{
	rm -rf lines; mkdir lines
	split -l 1 "$1" lines/l.
	n=0
	for l in lines/l.*; do
		${VALIDATE} "$l" >> lines.out || atf_fail "$1: invalid line"
		n=$((n + 1))
	done
	[ $n -gt 0 ] || atf_fail "$1: no lines"
}

# Wait (up to a minute, for slow or loaded hosts) for a file to have data.
wait_nonempty()
{
	i=0
	while [ ! -s "$1" ] && [ $i -lt 600 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	[ -s "$1" ] || atf_fail "$1 stayed empty"
}

# What newsyslog(8) does: rename away, put a new file in place, signal.
newsyslog_like()
{
	mv "$1" "$1.0"
	: > "$1.new"; chmod 0640 "$1.new"; mv "$1.new" "$1"
	[ -z "$2" ] || kill -HUP "$2"
}

atf_test_case hwstat_file_target
hwstat_file_target_head()
{
	atf_set "descr" "hwstat writes the otel.conf file target and follows rotation"
	atf_set "timeout" "120"
}
hwstat_file_target_body()
{
	[ -x "${HWSTAT}" ] || atf_skip "hwstat is not installed"
	mkdir logs
	config "export { target = \"file\"; directory = \"$(pwd)/logs\"; }"
	umask 022
	"${HWSTAT}" watch --format otel --interval 0.5 --duration 120 \
	    > hw.out 2> hw.err &
	pid=$!
	wait_nonempty logs/hwstat.jsonl
	atf_check -o inline:"640\n" stat -f %Lp logs/hwstat.jsonl
	# Rotation with the signal (the rc.d service under newsyslog).
	newsyslog_like logs/hwstat.jsonl $pid
	wait_nonempty logs/hwstat.jsonl
	# And without it: noticed at the next once-a-sample flush.
	mv logs/hwstat.jsonl.0 logs/hwstat.jsonl.1
	newsyslog_like logs/hwstat.jsonl
	wait_nonempty logs/hwstat.jsonl
	kill -TERM $pid
	wait $pid || atf_fail "hwstat failed: $(cat hw.err)"
	atf_check -o match:"Exporting to $(pwd)/logs/hwstat.jsonl" cat hw.err
	for f in logs/hwstat.jsonl.1 logs/hwstat.jsonl.0 logs/hwstat.jsonl; do
		validate_lines $f
	done
	atf_check -o match:"^resource service.name=hwstat$" \
	    -o match:"^resource host.id=11111111-2222-3333-4444-555555555555$" \
	    -o match:"^metric hwstat\." cat lines.out
	# Nothing went to the network or the spool.
	atf_check -o empty ls spool
	# The environment endpoint wins over the file target.
	receiver_start -n 1 -t 30
	atf_check -o ignore -e match:"Exporting to http://127.0.0.1" \
	    env OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:${PORT}" \
	    "${HWSTAT}" watch --format otel --interval 0.5 --duration 1.2
	receiver_wait
	# An unwritable directory is an error, not a silent fallback.
	config "export { target = \"file\"; directory = \"$(pwd)/nologs\"; }"
	atf_check -s not-exit:0 -o ignore -e match:"nologs/hwstat.jsonl" \
	    "${HWSTAT}" watch --format otel --interval 0.5 --duration 0.6
}

atf_init_test_cases()
{
	atf_add_test_case hwstat_system_config
	atf_add_test_case hwstat_system_spool
	atf_add_test_case hwstat_percore
	atf_add_test_case hwstat_precedence
	atf_add_test_case hwstat_bad_config
	atf_add_test_case hwstat_file_target
	atf_add_test_case dtrace_bad_config
	atf_add_test_case dtrace_profile_renders
	atf_add_test_case dtrace_system_metrics
}
