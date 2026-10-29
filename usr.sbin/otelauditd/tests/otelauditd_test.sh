#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# otelauditd(8) tests: BSM trails replayed through a local fake OTLP
# receiver, checked by an independent OTLP-JSON validator.
#

: ${OTELAUDITD:=/usr/sbin/otelauditd}
: ${OTEL_HELPERS:=$(atf_get_srcdir)/../otelconf}
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
	cat > otel.conf <<EOF
endpoint = "http://127.0.0.1:${PORT:-9}";
host_id_file = "";
# No spool: these cases do not test outages (and must not use the
# system spool when run as root).
spool { directory = "$(pwd)/no-spool"; }
$1
EOF
	OTELCONF_DEFAULTS=/nonexistent/otel.conf
	OTELCONF_FILE="$(pwd)/otel.conf"
	export OTELCONF_DEFAULTS OTELCONF_FILE
}

trail()
{
	"$(atf_get_srcdir)/mkaudittrail" "$@"
}

atf_test_case replay_logs
replay_logs_head()
{
	atf_set "descr" "A BSM trail becomes valid OTLP log records"
}
replay_logs_body()
{
	trail trail.bin
	receiver_start -n 1 -t 30
	config
	atf_check "${OTELAUDITD}" -f trail.bin
	receiver_wait
	atf_check -o match:"^POST /v1/logs HTTP/1.1" cat out/0000.hdr
	atf_check -o save:summary ${VALIDATE} out/0000.json
	atf_check -o match:"^resource service.name=otelauditd$" \
	    -o match:"probe=AUE_EXECVE,process.pid=4242,.*\] AUE_EXECVE execve\(2\) auid=1001 euid=0 egid=0 ruid=1001 pid=4242 args=\"ls -l a b\\\\\"c\\\\\\\\d\" path=/bin/ls result=success:0$" \
	    -o match:"probe=AUE_OPEN_R,process.pid=77,.*auid=- euid=1001 .* path=/etc/master.passwd text=\"note .*\" text=\"\" result=failure:13$" \
	    -o match:"probe=event_65000,.*result=success:7$" \
	    -o match:"pid=10 result=failure:2$" \
	    cat summary
	atf_check -o inline:"4\n" grep -c "^log " summary
	# Severity follows the outcome; the subject, outcome and path are
	# attributes, not only body text.
	atf_check \
	    -o match:"^log 9 \[.*probe=AUE_EXECVE,process.pid=4242,process.user.id=0,process.real_user.id=1001,process.group.id=0,process.real_group.id=[0-9]+,user.id=1001,otelauditd.result=success,otelauditd.return=0,file.path=/bin/ls\] " \
	    -o match:"^log 13 \[.*probe=AUE_OPEN_R,.*otelauditd.result=failure,otelauditd.return=13,file.path=/etc/master.passwd\] " \
	    -o match:"^log 9 \[.*probe=event_65000,.*otelauditd.return=7\] " \
	    -o match:"^log 13 \[.*\] .*pid=10 result=failure:2$" \
	    cat summary
	atf_check -o match:'"severityText":"WARN"' \
	    -o match:'"severityText":"INFO"' cat out/0000.json
	atf_check -s exit:1 grep -q hunter2 out/0000.json
}

atf_test_case record_count
record_count_head()
{
	atf_set "descr" "-c stops after the given number of records"
}
record_count_body()
{
	trail -n trail.bin
	receiver_start -n 1 -t 30
	config
	atf_check "${OTELAUDITD}" -f trail.bin -c 2
	receiver_wait
	atf_check -o inline:"2\n" sh -c \
	    "${OTEL_HELPERS}/otlp_json_validate out/0000.json | grep -c '^log '"
}

atf_test_case corrupt_trail
corrupt_trail_head()
{
	atf_set "descr" "Malformed records are skipped, not fatal"
}
corrupt_trail_body()
{
	trail -c trail.bin
	receiver_start -n 1 -t 30
	config
	atf_check -e match:"skipping a malformed audit record" \
	    "${OTELAUDITD}" -f trail.bin
	receiver_wait
	atf_check -o inline:"3\n" sh -c \
	    "${OTEL_HELPERS}/otlp_json_validate out/0000.json | grep -c '^log '"
	# A trail cut in the middle of a record.
	trail -n full.bin
	head -c 150 full.bin > cut.bin
	config
	atf_check -e match:"truncated record at the end" \
	    "${OTELAUDITD}" -f cut.bin
}

atf_test_case signal_stop
signal_stop_head()
{
	atf_set "descr" "SIGTERM stops otelauditd after flushing"
}
signal_stop_body()
{
	trail -n trail.bin
	mkfifo pipe
	receiver_start -n 1 -t 30
	config
	"${OTELAUDITD}" -f pipe &
	pid=$!
	# Keep the writer open so the reader blocks after four records.
	(cat trail.bin; sleep 30) > pipe &
	writer=$!
	# Long enough to take the four records even on a slow host.
	sleep 4
	kill -TERM $pid
	wait $pid || atf_fail "otelauditd exited with $?"
	kill $writer 2>/dev/null
	receiver_wait
	atf_check -o inline:"4\n" sh -c \
	    "${OTEL_HELPERS}/otlp_json_validate out/0000.json | grep -c '^log '"
}

atf_test_case faults
faults_head()
{
	atf_set "descr" "otelauditd refuses bad options and configuration"
}
faults_body()
{
	trail trail.bin
	config 'enable = false;'
	atf_check -s exit:1 -e match:"disabled in otel.conf" \
	    "${OTELAUDITD}" -f trail.bin
	cat > otel.conf <<EOF
endpoint = "nope";
EOF
	atf_check -s exit:1 -e match:"is not an http" \
	    "${OTELAUDITD}" -f trail.bin
	config
	atf_check -s exit:1 -e match:"cannot create the OTLP exporter" \
	    "${OTELAUDITD}" -f trail.bin -e "http://[::1"
	atf_check -s exit:1 -e match:"nonexistent.bin" \
	    "${OTELAUDITD}" -f nonexistent.bin
	atf_check -s exit:0 -e match:"read error" "${OTELAUDITD}" -f .
	atf_check -s exit:2 -e match:"usage" "${OTELAUDITD}" -f a -F lo
	atf_check -s exit:2 -e match:"usage" "${OTELAUDITD}" -x
	atf_check -s exit:2 -e match:"usage" "${OTELAUDITD}" extra
	atf_check -s exit:2 -e match:"-c must be" "${OTELAUDITD}" -c 0
	atf_check -s exit:2 -e match:"-c must be" "${OTELAUDITD}" -c 2x
	atf_check -s exit:1 -e match:"unknown user" \
	    "${OTELAUDITD}" -f trail.bin -u no-such-user-otel
	if [ "$(id -u)" -ne 0 ]; then
		atf_check -s exit:1 -e match:"cannot switch to user nobody" \
		    "${OTELAUDITD}" -f trail.bin -u nobody
	fi
}

atf_test_case device_access
device_access_head()
{
	atf_set "descr" "Without privileges the audit pipe cannot be opened"
	atf_set "require.user" "unprivileged"
}
device_access_body()
{
	config
	atf_check -s exit:1 -e match:"/dev/auditpipe" "${OTELAUDITD}" -c 1
}

atf_test_case live_pipe
live_pipe_head()
{
	atf_set "descr" "otelauditd exports live records from auditpipe(4)"
	atf_set "require.user" "root"
}
live_pipe_body()
{
	[ -c /dev/auditpipe ] || atf_skip "audit(4) is not available"
	atf_check -s exit:2 -e match:"invalid audit flags" \
	    "${OTELAUDITD}" -F no-such-class -c 1
	receiver_start -n 1 -t 60
	config
	# Several records: a burst queues more than one record per pipe
	# read, which otelauditd must split.
	"${OTELAUDITD}" -F ex -c 8 -u nobody &
	pid=$!
	# Generate exec events until otelauditd has taken them.
	i=0
	while kill -0 $pid 2>/dev/null && [ $i -lt 100 ]; do
		/usr/bin/true; /usr/bin/true; /usr/bin/true; /usr/bin/true
		sleep 0.2
		i=$((i + 1))
	done
	if kill -0 $pid 2>/dev/null; then
		kill $pid
		atf_skip "no exec audit records arrived (auditing is off?)"
	fi
	wait $pid || atf_fail "otelauditd exited with $?"
	receiver_wait
	atf_check -o match:"^log .*AUE_(EXECVE|EXEC|FEXECVE)" \
	    ${VALIDATE} out/0000.json
	# One record per log record: no body carries a second subject.
	atf_check -s exit:1 -x "${VALIDATE} out/0000.json | grep -q 'auid=.* auid='"
	# The system preselection, stopped by a signal while it waits on
	# the pipe: the interrupted read ends the loop cleanly.
	"${OTELAUDITD}" -e "http://127.0.0.1:9" > stop.out 2>&1 &
	pid=$!
	sleep 2
	kill -TERM $pid
	wait $pid || atf_fail "otelauditd exited with $? after SIGTERM"
}

atf_init_test_cases()
{
	atf_add_test_case replay_logs
	atf_add_test_case record_count
	atf_add_test_case corrupt_trail
	atf_add_test_case signal_stop
	atf_add_test_case faults
	atf_add_test_case device_access
	atf_add_test_case live_pipe
}
