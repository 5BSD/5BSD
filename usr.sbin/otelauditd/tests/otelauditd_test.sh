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
# The fake receiver stores JSON bodies; the protobuf transports have
# their own tests (lib/libotelexport/tests/otlppb_test).
protocol = "http/json";
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

# Validate every line of an OTLP JSON Lines file on its own; the
# summaries go to lines.out.
validate_lines()
{
	rm -rf lines; mkdir lines
	split -l 1 "$1" lines/l.
	n=0
	for l in lines/l.*; do
		"${OTEL_HELPERS}/otlp_json_validate" "$l" >> lines.out ||
		    atf_fail "$1: invalid line"
		n=$((n + 1))
	done
	[ $n -gt 0 ] || atf_fail "$1: no lines"
}

# What newsyslog(8) does: rename away, put a new file in place, signal.
newsyslog_like()
{
	mv "$1" "$1.0"
	: > "$1.new"; chmod 0640 "$1.new"; mv "$1.new" "$1"
	kill -HUP "$2"
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
	atf_check -s exit:1 -e match:"cannot create the exporter" \
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

atf_test_case file_target
file_target_head()
{
	atf_set "descr" "otel.conf's file target gets the log records; SIGHUP reopens"
	atf_set "timeout" "120"
}
file_target_body()
{
	trail trail.bin
	mkdir logs
	config "export { target = \"file\"; directory = \"$(pwd)/logs\"; }"
	umask 022
	atf_check "${OTELAUDITD}" -f trail.bin
	atf_check -o inline:"640\n" stat -f %Lp logs/otelauditd.jsonl
	validate_lines logs/otelauditd.jsonl
	atf_check -o inline:"4\n" grep -c "^log " lines.out
	atf_check -o match:"^resource service.name=otelauditd$" \
	    -o match:"^log 9 \[.*probe=AUE_EXECVE" cat lines.out

	# SIGHUP (newsyslog) reopens the file and does not stop the reader.
	rm -f logs/* lines.out
	trail -n trail.bin
	mkfifo pipe
	"${OTELAUDITD}" -f pipe &
	pid=$!
	(cat trail.bin; sleep 30) > pipe &
	writer=$!
	sleep 3
	newsyslog_like logs/otelauditd.jsonl $pid
	sleep 1
	kill -0 $pid || atf_fail "SIGHUP stopped otelauditd"
	kill -TERM $pid
	wait $pid || atf_fail "otelauditd exited with $?"
	kill $writer 2>/dev/null
	# Records written at exit go to the new file.
	validate_lines logs/otelauditd.jsonl
	atf_check -o inline:"4\n" grep -c "^log " lines.out
}

atf_test_case live_pipe_file_target
live_pipe_file_target_head()
{
	atf_set "descr" "live auditpipe records reach the file target while the pipe idles"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
live_pipe_file_target_body()
{
	[ -c /dev/auditpipe ] || atf_skip "audit(4) is not available"
	mkdir logs
	config "export { target = \"file\"; directory = \"$(pwd)/logs\"; }"
	# As root: the work directory is not reachable for another user.
	"${OTELAUDITD}" -F ex &
	pid=$!
	# Exec records until the first ones are written; the pipe is quiet
	# in between, so they are written by the idle flush, not at exit.
	i=0
	while [ ! -s logs/otelauditd.jsonl ] && [ $i -lt 60 ]; do
		/usr/bin/true; /usr/bin/true; /usr/bin/true
		sleep 0.5
		i=$((i + 1))
	done
	[ -s logs/otelauditd.jsonl ] || {
		kill $pid
		atf_skip "no exec audit records arrived (auditing is off?)"
	}
	# SIGHUP reopens (newsyslog); it does not stop the reader.
	newsyslog_like logs/otelauditd.jsonl $pid
	sleep 1
	kill -0 $pid || atf_fail "SIGHUP stopped otelauditd"
	/usr/bin/true; /usr/bin/true
	sleep 3
	kill -TERM $pid
	wait $pid || atf_fail "otelauditd exited with $?"
	validate_lines logs/otelauditd.jsonl.0
	atf_check -o match:"^log .*AUE_(EXECVE|EXEC|FEXECVE)" cat lines.out
}

atf_test_case pipe_drops
pipe_drops_head()
{
	atf_set "descr" "audit pipe drops are exported as the otelauditd.drops counter"
	atf_set "require.user" "root"
	atf_set "require.progs" "cc"
	atf_set "timeout" "120"
}
pipe_drops_body()
{
	[ -c /dev/auditpipe ] || atf_skip "audit(4) is not available"
	[ -f /usr/include/security/audit/audit_ioctl.h ] ||
	    atf_skip "audit_ioctl.h not installed"
	# A synthetic drop count (auditdrops.c): +3 at every pipe read.
	atf_check cc -shared -fPIC -o auditdrops.so \
	    "$(atf_get_srcdir)/auditdrops.c"
	mkdir logs
	config "export { target = \"file\"; directory = \"$(pwd)/logs\"; }"
	env LD_PRELOAD="$(pwd)/auditdrops.so" "${OTELAUDITD}" -F ex -c 4 &
	pid=$!
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
	validate_lines logs/otelauditd.jsonl
	# The first read reports 3, every later one 3 more: a cumulative
	# monotonic sum with the drop kind.
	atf_check -o match:"^point otelauditd.drops \[otelauditd.drop.kind=auditpipe\] 3$" \
	    cat lines.out
	atf_check -o match:"^log .*AUE_(EXECVE|EXEC|FEXECVE)" cat lines.out
}

atf_test_case pipe_file_full cleanup
pipe_file_full_head()
{
	atf_set "descr" "a file target that cannot be written is reported while the pipe idles"
	atf_set "require.user" "root"
	atf_set "timeout" "120"
}
pipe_file_full_body()
{
	[ -c /dev/auditpipe ] || atf_skip "audit(4) is not available"
	mkdir logs
	# A full file system under the target directory: opening the file
	# succeeds, the idle flush fails with ENOSPC.
	atf_check mount -t tmpfs -o size=1m tmpfs logs
	# The file exists (the exporter opens it), then the space runs out.
	touch logs/otelauditd.jsonl
	dd if=/dev/zero of=logs/fill bs=4k 2>/dev/null
	config "export { target = \"file\"; directory = \"$(pwd)/logs\"; }"
	"${OTELAUDITD}" -F ex > full.err 2>&1 &
	pid=$!
	# Exec records until the first write fails, then a quiet pipe: the
	# idle flush reports the unwritable file.
	i=0
	while ! grep -q "No space left" full.err && [ $i -lt 120 ]; do
		for j in 1 2 3 4 5 6 7 8 9 10; do /usr/bin/true; done
		sleep 0.5
		i=$((i + 1))
	done
	sleep 4
	kill -TERM $pid
	wait $pid
	grep -q "cannot write the audit records" full.err || {
		grep -q . full.err || atf_skip "no exec audit records arrived"
	}
	atf_check -o match:"cannot write the audit records" cat full.err
	atf_check -o match:"No space left on device" cat full.err
}
pipe_file_full_cleanup()
{
	umount logs 2>/dev/null || true
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
	atf_add_test_case file_target
	atf_add_test_case live_pipe_file_target
	atf_add_test_case pipe_drops
	atf_add_test_case pipe_file_full
}
