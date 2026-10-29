#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Tests for the OpenTelemetry rc.d scripts: switch inheritance, start
# refusal, agent configuration generation and real start/stop through
# daemon(8) with stand-in programs.  The Fluent Bit binary itself is
# replaced by a stand-in until it is imported into the base system.
#

: ${OTELCONF:=/usr/sbin/otelconf}
: ${OTEL_RCD:=/etc/rc.d}

# Write rc.conf.test from the arguments (one assignment each) plus the
# sandbox locations, then run "service verb" in a clean shell.
rc_setup()
{
	: > rc.conf.test
	for a in "$@"; do
		echo "$a" >> rc.conf.test
	done
	cat >> rc.conf.test <<EOF
otel_rundir="$(pwd)/run"
otelconf_program="$(pwd)/otelconf.sh"
fluentbit_runas=""
EOF
	cat > otelconf.sh <<EOF
#!/bin/sh
exec "${OTELCONF}" -d /nonexistent/otel.conf -f "$(pwd)/local.conf" "\$@"
EOF
	chmod +x otelconf.sh
	cat > local.conf <<EOF
host_id_file = "";
spool { directory = "$(pwd)/spool"; }
agent { upstream = "http://collector.invalid:4318"; tail = []; }
EOF
	cat > ./rc_run <<EOF
#!/bin/sh
# rc_run service verb: run an rc.d script against rc.conf.test.
cat > "$(pwd)/harness.sh" <<HARNESS
_rc_conf_loaded=true
. "$(pwd)/rc.conf.test"
set -- \$2
. "${OTEL_RCD}/\$1"
HARNESS
exec /bin/sh "$(pwd)/harness.sh"
EOF
	chmod +x rc_run
}


# A stand-in program that records its arguments and environment.
fake_program()
{
	cat > "$1" <<EOF
#!/bin/sh
echo "\$@" > "$(pwd)/$1.args"
echo "endpoint=\${OTEL_EXPORTER_OTLP_ENDPOINT}" >> "$(pwd)/$1.args"
exec sleep 60
EOF
	chmod +x "$1"
}

wait_for()
{
	i=0
	while [ ! -s "$1" ] && [ $i -lt 100 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	[ -s "$1" ] || atf_fail "$1 did not appear"
}

atf_test_case inherit_switch
inherit_switch_head()
{
	atf_set "descr" "Empty service switches follow otel_enable"
}
inherit_switch_body()
{
	for s in fluentbit otel_hwstat otelpfd otelauditd otel_dtrace; do
		rc_setup 'otel_enable="NO"'
		atf_check -s exit:1 -o ignore ./rc_run $s enabled
		rc_setup 'otel_enable="YES"'
		atf_check -o match:"^${s}_enable=\"YES\"" ./rc_run $s rcvar
		atf_check -o ignore ./rc_run $s enabled
		rc_setup 'otel_enable="YES"' "${s}_enable=\"NO\""
		atf_check -s exit:1 -o ignore ./rc_run $s enabled
		rc_setup 'otel_enable="NO"' "${s}_enable=\"YES\""
		atf_check -o ignore ./rc_run $s enabled
		# Unset in rc.conf entirely: off.
		rc_setup
		atf_check -s exit:1 -o ignore ./rc_run $s enabled
	done
}

atf_test_case agent_pending
agent_pending_head()
{
	atf_set "descr" "fluentbit refuses to start without the agent binary"
}
agent_pending_body()
{
	rc_setup 'otel_enable="YES"' \
	    "fluentbit_bin=\"$(pwd)/no-fluent-bit\""
	atf_check -s exit:1 -o empty \
	    -e match:"is not installed; the Fluent Bit import" \
	    ./rc_run fluentbit start
	atf_check -s exit:1 -o empty -e match:"is not installed" \
	    ./rc_run fluentbit oneconfigtest
}

atf_test_case agent_configtest
agent_configtest_head()
{
	atf_set "descr" "fluentbit renders, installs and dry-runs its config"
}
agent_configtest_body()
{
	cat > fluent-bit <<EOF
#!/bin/sh
echo "\$@" > "$(pwd)/fb.args"
exit \${FB_EXIT:-0}
EOF
	chmod +x fluent-bit
	rc_setup "fluentbit_bin=\"$(pwd)/fluent-bit\""
	atf_check -o match:"fluent-bit.yaml: OK" ./rc_run fluentbit oneconfigtest
	atf_check -o inline:"--dry-run -c $(pwd)/run/fluent-bit.yaml\n" \
	    cat fb.args
	atf_check -o inline:"600\n" stat -f %Lp run/fluent-bit.yaml
	atf_check -o match:"host: 'collector.invalid'" cat run/fluent-bit.yaml
	atf_check -o inline:"750\n" stat -f %Lp spool/fluent-bit

	# A rejected configuration stops the start.
	FB_EXIT=1; export FB_EXIT
	atf_check -s exit:1 -e match:"rejected by fluent-bit --dry-run" \
	    ./rc_run fluentbit oneconfigtest
	unset FB_EXIT

	# No upstream: otelconf refuses and nothing is started.
	echo 'host_id_file = "";' > local.conf
	atf_check -s exit:1 -e match:"agent.upstream is not set" \
	    ./rc_run fluentbit oneconfigtest

	# Disabled configuration.
	echo 'enable = false;' > local.conf
	atf_check -s exit:1 -e match:"disabled" ./rc_run fluentbit oneconfigtest

	# An administrator configuration bypasses otelconf.
	echo "pipeline: {}" > own.yaml
	rc_setup "fluentbit_bin=\"$(pwd)/fluent-bit\"" \
	    "fluentbit_config=\"$(pwd)/own.yaml\""
	echo 'enable = false;' > local.conf
	atf_check -o match:"own.yaml: OK" ./rc_run fluentbit oneconfigtest
	atf_check -o inline:"--dry-run -c $(pwd)/own.yaml\n" cat fb.args
}

atf_test_case agent_start_stop
agent_start_stop_head()
{
	atf_set "descr" "fluentbit starts the agent under daemon(8)"
	# rc.subr applies login-class limits, which needs root.
	atf_set "require.user" "root"
}
agent_start_stop_body()
{
	cat > fluent-bit <<EOF
#!/bin/sh
case "\$1" in --dry-run) exit 0;; esac
echo "\$@" > "$(pwd)/fb.args"
exec sleep 60
EOF
	chmod +x fluent-bit
	rc_setup 'fluentbit_enable="YES"' \
	    "fluentbit_bin=\"$(pwd)/fluent-bit\"" 'fluentbit_flags="-q"'
	atf_check -o match:"Starting fluentbit" ./rc_run fluentbit start
	wait_for fb.args
	atf_check -o inline:"-c $(pwd)/run/fluent-bit.yaml -q\n" cat fb.args
	atf_check -o match:"is running" ./rc_run fluentbit status
	atf_check -o match:"Stopping fluentbit" ./rc_run fluentbit stop
	atf_check -s exit:1 -o match:"is not running" ./rc_run fluentbit status
}

# Start and stop one emitter with a stand-in program.
emitter_cycle()
{
	svc=$1 prog=$2 expect=$3
	shift 3
	fake_program $prog
	rc_setup 'otel_enable="YES"' "${svc}_bin=\"$(pwd)/$prog\"" "$@"
	atf_check -o match:"Starting $svc" ./rc_run $svc start
	wait_for $prog.args
	atf_check -o inline:"$expect" cat $prog.args
	atf_check -o match:"is running" ./rc_run $svc status
	atf_check -o match:"Stopping $svc" ./rc_run $svc stop
	atf_check -s exit:1 -o match:"is not running" ./rc_run $svc status
	rm -f $prog.args
}

atf_test_case emitters_start_stop
emitters_start_stop_head()
{
	atf_set "descr" "Emitter scripts build the documented command lines"
	# rc.subr applies login-class limits, which needs root.
	atf_set "require.user" "root"
}
emitters_start_stop_body()
{
	emitter_cycle otel_hwstat hwstat \
	    "watch --format otel --interval 10\nendpoint=\n"
	emitter_cycle otel_hwstat hwstat \
	    "watch --format otel --interval 2 --per-core\nendpoint=http://e:1\n" \
	    'otel_hwstat_interval="2"' 'otel_hwstat_flags="--per-core"' \
	    'otel_endpoint="http://e:1"'
	emitter_cycle otelpfd otelpfd "-u _otel\nendpoint=\n"
	emitter_cycle otelpfd otelpfd "-u nobody -i 5\nendpoint=http://e:2\n" \
	    'otelpfd_runas="nobody"' 'otelpfd_flags="-i 5"' \
	    'otel_endpoint="http://e:2"'
	emitter_cycle otelauditd otelauditd "-u _otel\nendpoint=\n"
	emitter_cycle otelauditd otelauditd \
	    "-u nobody -n\nendpoint=http://e:3\n" \
	    'otelauditd_runas="nobody"' 'otelauditd_flags="-n"' \
	    'otel_endpoint="http://e:3"'
	if kldstat -q -m dtrace; then
		emitter_cycle otel_dtrace bsdinstruments \
		    "watch system-metrics --format otel --duration 60\nendpoint=http://e:4\n" \
		    'otel_endpoint="http://e:4"'
	fi
}

atf_test_case emitters_refuse
emitters_refuse_head()
{
	atf_set "descr" "Emitters refuse to start when misconfigured"
}
emitters_refuse_body()
{
	for s in otel_hwstat otelpfd otelauditd otel_dtrace; do
		rc_setup 'otel_enable="YES"' "${s}_bin=\"$(pwd)/none\""
		atf_check -s exit:1 -e match:"none is not installed" \
		    ./rc_run $s start
		fake_program prog
		rc_setup 'otel_enable="YES"' "${s}_bin=\"$(pwd)/prog\""
		echo 'enable = false;' > local.conf
		atf_check -s exit:1 -e match:"disabled" ./rc_run $s start
		echo 'enable = maybe;' > local.conf
		atf_check -s exit:1 -e match:"must be true or false" \
		    ./rc_run $s start
	done
	if ! kldstat -q -m dtrace; then
		fake_program prog
		rc_setup 'otel_enable="YES"' \
		    "otel_dtrace_bin=\"$(pwd)/prog\""
		atf_check -s exit:1 -e match:"dtraceall_load" \
		    ./rc_run otel_dtrace start
	fi
}

atf_init_test_cases()
{
	atf_add_test_case inherit_switch
	atf_add_test_case agent_pending
	atf_add_test_case agent_configtest
	atf_add_test_case agent_start_stop
	atf_add_test_case emitters_start_stop
	atf_add_test_case emitters_refuse
}
