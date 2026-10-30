#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# otelconf(8) tests: validation and queries.
#

: ${OTELCONF:=/usr/sbin/otelconf}

# otelconf with only the local file (the defaults path does not exist).
OC="${OTELCONF} -d /nonexistent/otel.conf -f local.conf"

defaults_file()
{
	echo "$(atf_get_srcdir)/otel.conf.defaults"
}

atf_test_case shipped_files
shipped_files_head()
{
	atf_set "descr" "The shipped defaults and local files are valid"
}
shipped_files_body()
{
	cp "$(atf_get_srcdir)/otel.conf.sample" local.conf
	chmod 0644 local.conf
	# The shipped files name no export target: there is no local
	# collector in the base system.
	atf_check -o inline:"otel.conf: OK (no export target)\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf check
	atf_check -s exit:4 -e match:"no export target" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf check -eqt
	atf_check -o inline:"true\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf get enable
	atf_check -o inline:"\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf get endpoint
	atf_check -o inline:"/var/spool/otel\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf \
	    get spool.directory
	atf_check -o match:"^service.namespace=5bsd$" \
	    -o match:"^deployment.environment.name=production$" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf get resource
	# Nothing of the removed local agent is accepted any more.
	echo 'agent { upstream = "http://c:4318"; }' >> local.conf
	atf_check -s exit:1 -e match:"unknown key agent" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf check
}

atf_test_case check_states
check_states_head()
{
	atf_set "descr" "check reports valid, disabled and invalid files"
}
check_states_body()
{
	echo 'enable = false;' > local.conf
	atf_check -o inline:"otel.conf: OK (disabled) (no export target)\n" ${OC} check
	atf_check -s exit:3 -e match:"disabled" ${OC} check -e
	atf_check -s exit:3 -e match:"disabled" ${OC} check -eq
	echo 'enable = true;' > local.conf
	atf_check ${OC} check -eq
	atf_check -o inline:"otel.conf: OK (no export target)\n" ${OC} check
	atf_check -s exit:4 -e match:"no export target" ${OC} check -t
	echo 'endpoint = "http://c:4318";' > local.conf
	atf_check -o inline:"otel.conf: OK\n" ${OC} check -et
	# Disabled wins over a missing target.
	echo 'enable = false;' > local.conf
	atf_check -s exit:3 -e match:"disabled" ${OC} check -eqt
	echo 'endpoint = "gopher://x";' > local.conf
	atf_check -s exit:1 -e match:"local.conf: endpoint .* is not an http" \
	    ${OC} check
	atf_check -s exit:2 -e match:"usage" ${OC} check -z
	atf_check -s exit:2 -e match:"usage" ${OC} check extra
}

atf_test_case show_redacts
show_redacts_head()
{
	atf_set "descr" "show prints every key and redacts credentials"
}
show_redacts_body()
{
	printf 'Authorization: Bearer s3cret\n' > creds
	chmod 0600 creds
	cat > local.conf <<EOF
headers_file = "$(pwd)/creds";
host_id_file = "";
resource { team = "infra"; }
EOF
	atf_check -o save:show.out ${OC} show
	atf_check -o match:"^enable = true$" -o match:"^timeout_ms = 10000$" \
	    -o match:"^endpoint = $" -o match:"^spool.max_bytes = " \
	    -o match:"^Authorization=<redacted>$" -o match:"^team=infra$" \
	    -o match:"^# headers \(1, values redacted\)$" \
	    -o not-match:"agent" cat show.out
	atf_check -s exit:1 grep -q s3cret show.out
	atf_check -s exit:2 -e match:"usage" ${OC} show extra
}

atf_test_case get_keys
get_keys_head()
{
	atf_set "descr" "get prints each supported key"
}
get_keys_body()
{
	cat > local.conf <<EOF
enable = false;
endpoint = "https://c.example:4318";
compression = "none";
timeout_ms = 5;
headers_file = "";
host_id_file = "/nonexistent";
spool { directory = "/var/spool/x"; max_bytes = 2097152; }
EOF
	atf_check -o inline:"false\n" ${OC} get enable
	atf_check -o inline:"https://c.example:4318\n" ${OC} get endpoint
	atf_check -o inline:"http/json\n" ${OC} get protocol
	atf_check -o inline:"none\n" ${OC} get compression
	atf_check -o inline:"5\n" ${OC} get timeout_ms
	atf_check -o inline:"\n" ${OC} get headers_file
	atf_check -o inline:"/nonexistent\n" ${OC} get host_id_file
	atf_check -o inline:"2097152\n" ${OC} get spool.max_bytes
	atf_check -o inline:"/var/spool/x\n" ${OC} get spool.directory
	atf_check -o empty ${OC} get resource
	atf_check -s exit:2 -e match:"unknown key: agent.upstream" \
	    ${OC} get agent.upstream
	atf_check -s exit:2 -e match:"unknown key: nope" ${OC} get nope
	atf_check -s exit:2 -e match:"usage" ${OC} get
	atf_check -s exit:2 -e match:"usage" ${OC} get a b
}

atf_test_case usage_errors
usage_errors_head()
{
	atf_set "descr" "Global usage errors exit 2"
}
usage_errors_body()
{
	atf_check -s exit:2 -e match:"usage" "${OTELCONF}"
	atf_check -s exit:2 -e match:"usage" "${OTELCONF}" -x check
	atf_check -s exit:2 -e match:"usage" "${OTELCONF}" frobnicate
}

atf_init_test_cases()
{
	atf_add_test_case shipped_files
	atf_add_test_case check_states
	atf_add_test_case show_redacts
	atf_add_test_case get_keys
	atf_add_test_case usage_errors
}
