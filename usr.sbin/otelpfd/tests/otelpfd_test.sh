#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# otelpfd(8) tests: replayed pf status through a local fake OTLP
# receiver, checked by an independent OTLP-JSON validator.
#

: ${OTELPFD:=/usr/sbin/otelpfd}
: ${OTEL_HELPERS:=$(atf_get_srcdir)/../otelconf}

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
resource { "deployment.environment.name" = "test"; }
# No spool: these cases do not test outages (and must not use the
# system spool when run as root).
spool { directory = "$(pwd)/no-spool"; }
$1
EOF
	OTELCONF_DEFAULTS=/nonexistent/otel.conf
	OTELCONF_FILE="$(pwd)/otel.conf"
	export OTELCONF_DEFAULTS OTELCONF_FILE
}

mkstatus()
{
	"$(atf_get_srcdir)/mkpfstatus" "$@"
}

atf_test_case replay_metrics
replay_metrics_head()
{
	atf_set "descr" "A replayed pf status becomes valid OTLP metrics"
}
replay_metrics_body()
{
	mkstatus status.bin 1
	receiver_start -n 1 -t 30
	config
	atf_check "${OTELPFD}" -f status.bin -c 1
	receiver_wait
	atf_check -o match:"^POST /v1/metrics HTTP/1.1" \
	    -o match:"^Content-Encoding: gzip" cat out/0000.hdr
	atf_check -o save:summary "${OTEL_HELPERS}/otlp_json_validate" \
	    out/0000.json
	atf_check -o match:"^resource service.name=otelpfd$" \
	    -o match:"^resource deployment.environment.name=test$" \
	    -o match:"^metric otelpfd.pf.states gauge" \
	    -o match:"^point otelpfd.pf.states \[\] 100$" \
	    -o match:"^point otelpfd.pf.running \[\] 1$" \
	    -o match:"^metric otelpfd.pf.reasons sum monotonic=1$" \
	    -o match:"^point otelpfd.pf.reasons \[reason=match\] 1$" \
	    -o match:"^point otelpfd.pf.reasons \[reason=no-route\] 17$" \
	    -o match:"^point otelpfd.pf.limits \[limit=max states per rule\] 18$" \
	    -o match:"^point otelpfd.pf.state_operations \[operation=search\] 28$" \
	    -o match:"^point otelpfd.pf.packets \[network.type=ipv4,network.io.direction=receive,action=pass\] 37$" \
	    -o match:"^point otelpfd.pf.packets \[network.type=ipv4,network.io.direction=receive,action=block\] 38$" \
	    -o match:"^point otelpfd.pf.bytes \[network.type=ipv6,network.io.direction=transmit\] 52$" \
	    cat summary
}

atf_test_case replay_series
replay_series_head()
{
	atf_set "descr" "Each interval exports the next status sample"
}
replay_series_body()
{
	mkstatus status.bin 3
	receiver_start -n 0 -t 4
	config 'compression = "none";'
	atf_check "${OTELPFD}" -f status.bin -i 0.2
	receiver_wait
	atf_check -s exit:1 grep -qi "^Content-Encoding" out/0000.hdr
	cat out/*.json > /dev/null
	for f in out/*.json; do
		atf_check -o ignore "${OTEL_HELPERS}/otlp_json_validate" "$f"
	done
	atf_check -o match:"\] 100$" -o match:"\] 101$" -o match:"\] 102$" \
	    sh -c "${OTEL_HELPERS}/otlp_json_validate out/*.json | \
	    grep '^point otelpfd.pf.states '"
	# The replay ended after three samples: no fourth.
	atf_check -s exit:1 sh -c "${OTEL_HELPERS}/otlp_json_validate \
	    out/*.json | grep -q '^point otelpfd.pf.states \[\] 103$'"
}

atf_test_case cli_endpoint
cli_endpoint_head()
{
	atf_set "descr" "-e overrides otel.conf and drops its credentials"
}
cli_endpoint_body()
{
	mkstatus status.bin 1
	receiver_start -n 1 -t 30
	printf 'Authorization: Bearer system\n' > creds
	chmod 0600 creds
	PORT_SAVED=$PORT
	PORT=9 config "headers_file = \"$(pwd)/creds\";"
	atf_check "${OTELPFD}" -f status.bin -c 1 \
	    -e "http://127.0.0.1:${PORT_SAVED}"
	receiver_wait
	atf_check -s exit:1 grep -qi "^Authorization" out/0000.hdr
}

atf_test_case service_env
service_env_head()
{
	atf_set "descr" "OTEL_SERVICE_NAME and OTEL_EXPORTER_OTLP_TIMEOUT apply"
}
service_env_body()
{
	mkstatus status.bin 1
	receiver_start -n 1 -t 30
	config
	atf_check env OTEL_SERVICE_NAME=edge-pf OTEL_EXPORTER_OTLP_TIMEOUT=0 \
	    "${OTELPFD}" -f status.bin -c 1
	receiver_wait
	# The service name is a resource attribute; metric names keep the
	# instrumentation scope, otelpfd.
	atf_check -o match:"^resource service.name=edge-pf$" \
	    -o match:"^scope otelpfd$" \
	    -o match:"^point otelpfd.pf.states \[\] 100$" \
	    -o not-match:"edge-pf.pf" \
	    "${OTEL_HELPERS}/otlp_json_validate" out/0000.json
}

atf_test_case credentials
credentials_head()
{
	atf_set "descr" "otel.conf credentials reach the configured endpoint"
}
credentials_body()
{
	mkstatus status.bin 1
	receiver_start -n 1 -t 30
	printf 'Authorization: Bearer system\n' > creds
	chmod 0600 creds
	config "headers_file = \"$(pwd)/creds\";"
	atf_check "${OTELPFD}" -f status.bin -c 1
	receiver_wait
	atf_check -o match:"^Authorization: Bearer system" cat out/0000.hdr
	chmod 0644 creds
	atf_check -s exit:1 -e match:"use mode 0600" \
	    "${OTELPFD}" -f status.bin -c 1
}

atf_test_case faults
faults_head()
{
	atf_set "descr" "otelpfd refuses bad input and configuration"
}
faults_body()
{
	mkstatus -t status.bin 1
	config 'enable = false;'
	atf_check -s exit:1 -e match:"disabled in otel.conf" \
	    "${OTELPFD}" -f status.bin -c 1
	config 'timeout_ms = "x";'
	atf_check -s exit:1 -e match:"timeout_ms must be an integer" \
	    "${OTELPFD}" -f status.bin -c 1
	config
	atf_check -s exit:1 -e match:"truncated status record" \
	    "${OTELPFD}" -f status.bin -c 2 -i 0.1
	atf_check -s exit:1 -e match:"nonexistent.bin" \
	    "${OTELPFD}" -f nonexistent.bin
	atf_check -s exit:1 -e match:"read" "${OTELPFD}" -f . -c 1
	atf_check -s exit:1 -e match:"cannot create the OTLP exporter" \
	    "${OTELPFD}" -f status.bin -e "http://[::1" -c 1
	atf_check -s exit:2 -e match:"usage" "${OTELPFD}" -x
	atf_check -s exit:2 -e match:"usage" "${OTELPFD}" extra
	atf_check -s exit:2 -e match:"-c must be" "${OTELPFD}" -c 0
	atf_check -s exit:2 -e match:"-c must be" "${OTELPFD}" -c 1x
	atf_check -s exit:2 -e match:"-i must be" "${OTELPFD}" -i 0.01
	atf_check -s exit:2 -e match:"-i must be" "${OTELPFD}" -i 5s
	atf_check -s exit:1 -e match:"unknown user" \
	    "${OTELPFD}" -f status.bin -c 1 -u no-such-user-otel
	if [ "$(id -u)" -ne 0 ]; then
		atf_check -s exit:1 -e match:"cannot switch to user nobody" \
		    "${OTELPFD}" -f status.bin -c 1 -u nobody
	fi
}

atf_test_case signal_stop
signal_stop_head()
{
	atf_set "descr" "SIGTERM stops otelpfd after flushing its metrics"
}
signal_stop_body()
{
	mkstatus status.bin 100
	receiver_start -n 1 -t 30
	config
	"${OTELPFD}" -f status.bin -i 60 &
	pid=$!
	# Long enough for the first sample even on a slow (emulated) host.
	sleep 3
	kill -TERM $pid
	wait $pid || atf_fail "otelpfd exited with $?"
	receiver_wait
	atf_check -o match:"^point otelpfd.pf.states \[\] 100$" \
	    "${OTEL_HELPERS}/otlp_json_validate" out/0000.json
}

atf_test_case device_access
device_access_head()
{
	atf_set "descr" "Without privileges /dev/pf cannot be opened"
	atf_set "require.user" "unprivileged"
}
device_access_body()
{
	config
	atf_check -s exit:1 -e match:"/dev/pf" "${OTELPFD}" -c 1
}

atf_test_case drop_privileges
drop_privileges_head()
{
	atf_set "descr" "otelpfd keeps exporting after dropping to a user"
	atf_set "require.user" "root"
}
drop_privileges_body()
{
	mkstatus status.bin 2
	chmod 0600 status.bin
	receiver_start -n 0 -t 5
	config
	atf_check "${OTELPFD}" -f status.bin -c 2 -i 0.2 -u nobody
	receiver_wait
	# Each sample may travel in its own request.
	atf_check -o match:"^point otelpfd.pf.states \[\] 100$" \
	    -o match:"^point otelpfd.pf.states \[\] 101$" \
	    "${OTEL_HELPERS}/otlp_json_validate" out/*.json
}

atf_test_case live_pf
live_pf_head()
{
	atf_set "descr" "otelpfd reads the running pf(4) through /dev/pf"
	atf_set "require.user" "root"
}
live_pf_body()
{
	[ -c /dev/pf ] || atf_skip "pf(4) is not loaded"
	receiver_start -n 1 -t 30
	config
	atf_check "${OTELPFD}" -c 1 -u nobody
	receiver_wait
	atf_check -o match:"^point otelpfd.pf.running \[\] [01]$" \
	    -o match:"^point otelpfd.pf.states \[\] [0-9]+$" \
	    "${OTEL_HELPERS}/otlp_json_validate" out/0000.json
}

atf_init_test_cases()
{
	atf_add_test_case replay_metrics
	atf_add_test_case replay_series
	atf_add_test_case cli_endpoint
	atf_add_test_case service_env
	atf_add_test_case credentials
	atf_add_test_case faults
	atf_add_test_case signal_stop
	atf_add_test_case device_access
	atf_add_test_case drop_privileges
	atf_add_test_case live_pf
}
