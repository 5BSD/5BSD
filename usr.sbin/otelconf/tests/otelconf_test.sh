#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# otelconf(8) tests: validation, queries and Fluent Bit rendering.
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
	atf_check -o inline:"otel.conf: OK\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf check
	atf_check -o inline:"true\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf get enable
	atf_check -o inline:"http://localhost:4318\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf get endpoint
	atf_check -o inline:"/var/spool/otel\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf \
	    get spool.directory
	atf_check -o inline:"/var/log/messages\n" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf get agent.tail
	atf_check -o match:"^service.namespace=5bsd$" \
	    -o match:"^deployment.environment.name=production$" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf get resource
	# The shipped defaults do not start a forwarding agent.
	atf_check -s exit:1 -e match:"agent.upstream is not set" \
	    "${OTELCONF}" -d "$(defaults_file)" -f local.conf fluentbit
}

atf_test_case check_states
check_states_head()
{
	atf_set "descr" "check reports valid, disabled and invalid files"
}
check_states_body()
{
	echo 'enable = false;' > local.conf
	atf_check -o inline:"otel.conf: OK (disabled)\n" ${OC} check
	atf_check -s exit:3 -e match:"disabled" ${OC} check -e
	atf_check -s exit:3 -e match:"disabled" ${OC} check -eq
	echo 'enable = true;' > local.conf
	atf_check ${OC} check -eq
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
agent { tail = [ "/var/log/a", "/var/log/b" ]; }
EOF
	atf_check -o save:show.out ${OC} show
	atf_check -o match:"^enable = true$" -o match:"^timeout_ms = 10000$" \
	    -o match:"^agent.tls_verify = true$" \
	    -o match:"^Authorization=<redacted>$" -o match:"^team=infra$" \
	    -o match:"^# agent.tail \(2\)$" -o match:"^/var/log/b$" \
	    cat show.out
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
spool { max_bytes = 2097152; }
agent {
	listen = "[::1]:14318";
	upstream = "https://up.example";
	upstream_protocol = "grpc";
	headers_file = "/etc/otel/up";
	tls_verify = false;
	log_level = "warn";
	tail = [];
}
EOF
	atf_check -o inline:"false\n" ${OC} get enable
	atf_check -o inline:"https://c.example:4318\n" ${OC} get endpoint
	atf_check -o inline:"http/protobuf\n" ${OC} get protocol
	atf_check -o inline:"none\n" ${OC} get compression
	atf_check -o inline:"5\n" ${OC} get timeout_ms
	atf_check -o inline:"\n" ${OC} get headers_file
	atf_check -o inline:"/nonexistent\n" ${OC} get host_id_file
	atf_check -o inline:"2097152\n" ${OC} get spool.max_bytes
	atf_check -o inline:"[::1]:14318\n" ${OC} get agent.listen
	atf_check -o inline:"::1\n" ${OC} get agent.listen.host
	atf_check -o inline:"14318\n" ${OC} get agent.listen.port
	atf_check -o inline:"https://up.example\n" ${OC} get agent.upstream
	atf_check -o inline:"grpc\n" ${OC} get agent.upstream_protocol
	atf_check -o inline:"/etc/otel/up\n" ${OC} get agent.headers_file
	atf_check -o inline:"false\n" ${OC} get agent.tls_verify
	atf_check -o inline:"warn\n" ${OC} get agent.log_level
	atf_check -o empty ${OC} get agent.tail
	atf_check -o empty ${OC} get resource
	echo 'agent { listen = "127.0.0.1:4318"; }' > local.conf
	atf_check -o inline:"127.0.0.1\n" ${OC} get agent.listen.host
	atf_check -o inline:"4318\n" ${OC} get agent.listen.port
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

atf_test_case fluentbit_render
fluentbit_render_head()
{
	atf_set "descr" "fluentbit renders the expected agent configuration"
}
fluentbit_render_body()
{
	printf "Authorization: Bearer it's\nX-Scope-OrgID: t1\n" > up.headers
	chmod 0600 up.headers
	cat > local.conf <<EOF
compression = "gzip";
host_id_file = "";
spool { directory = "/var/spool/otel"; max_bytes = 268435456; }
agent {
	listen = "127.0.0.1:4318";
	upstream = "https://collector.example:4318/otlp/";
	headers_file = "$(pwd)/up.headers";
	tail = [ "/var/log/messages", "/var/log/daemon.log" ];
}
EOF
	atf_check -o save:fb.yaml ${OC} fluentbit
	atf_check -o file:"$(atf_get_srcdir)/fluentbit_full.yaml" cat fb.yaml

	# Plain HTTP, gRPC, no tail, no credentials, IPv6 listener.
	cat > local.conf <<EOF
compression = "none";
host_id_file = "";
agent {
	listen = "[::1]:14318";
	upstream = "http://10.0.0.1";
	upstream_protocol = "grpc";
	tls_verify = false;
	log_level = "debug";
	tail = [];
}
EOF
	atf_check -o file:"$(atf_get_srcdir)/fluentbit_min.yaml" ${OC} fluentbit
}

atf_test_case fluentbit_output
fluentbit_output_head()
{
	atf_set "descr" "fluentbit -o writes a private file atomically"
}
fluentbit_output_body()
{
	cat > local.conf <<EOF
host_id_file = "";
agent { upstream = "http://collector:4318"; tail = []; }
EOF
	mkdir out
	umask 022
	atf_check ${OC} fluentbit -o out/fluent-bit.yaml
	atf_check -o inline:"600\n" stat -f %Lp out/fluent-bit.yaml
	atf_check -o match:"host: 'collector'" cat out/fluent-bit.yaml
	# Replacing keeps a single file and no temporaries.
	atf_check ${OC} fluentbit -o out/fluent-bit.yaml
	atf_check -o inline:"fluent-bit.yaml\n" ls -A out
	# Failures leave no temporary file behind.
	atf_check -s exit:1 -e match:"rename" ${OC} fluentbit -o out
	atf_check -o inline:"fluent-bit.yaml\n" ls -A out
	atf_check -s exit:1 -e match:"nonexistent" \
	    ${OC} fluentbit -o nonexistent/dir/x.yaml
	long=$(printf '%01024d' 0)
	atf_check -s exit:1 -e match:"path too long" \
	    ${OC} fluentbit -o "$long/x"
	# Short enough as a path, but no room for the temporary name.
	c=$(printf '%0202d' 0)
	atf_check -s exit:1 -e match:"path too long" \
	    ${OC} fluentbit -o "/$c/$c/$c/$c/$c/x"
	atf_check -s exit:2 -e match:"usage" ${OC} fluentbit -u root
	atf_check -s exit:2 -e match:"usage" ${OC} fluentbit -q
	atf_check -s exit:2 -e match:"usage" ${OC} fluentbit extra
	# Handing the file to oneself works without privilege; to another
	# user it needs root and fails cleanly otherwise.
	atf_check ${OC} fluentbit -o out/self.yaml -u "$(id -un)"
	if [ "$(id -u)" -ne 0 ]; then
		atf_check -s exit:1 -e match:"fchown" \
		    ${OC} fluentbit -o out/root.yaml -u root
		atf_check -o inline:"fluent-bit.yaml\nself.yaml\n" ls -A out
	fi
	# A closed standard output is reported.
	atf_check -s exit:1 -e ignore sh -c "${OC} fluentbit >&-"
	atf_check -s exit:1 -e match:"unknown user" \
	    ${OC} fluentbit -o out/x.yaml -u no-such-user-otel
}

atf_test_case fluentbit_chown
fluentbit_chown_head()
{
	atf_set "descr" "fluentbit -u hands the file to the agent user"
	atf_set "require.user" "root"
}
fluentbit_chown_body()
{
	cat > local.conf <<EOF
host_id_file = "";
agent { upstream = "http://collector:4318"; tail = []; }
EOF
	atf_check ${OC} fluentbit -o fb.yaml -u nobody
	atf_check -o inline:"nobody 600\n" stat -f "%Su %Lp" fb.yaml
}

atf_test_case fluentbit_faults
fluentbit_faults_head()
{
	atf_set "descr" "fluentbit refuses disabled, unsafe or broken input"
}
fluentbit_faults_body()
{
	printf 'Authorization: Bearer x\n' > up.headers
	chmod 0644 up.headers
	cat > local.conf <<EOF
host_id_file = "";
agent { upstream = "http://c:4318"; headers_file = "$(pwd)/up.headers"; }
EOF
	atf_check -s exit:1 -e match:"agent.headers_file: .*mode 0644" \
	    ${OC} fluentbit
	atf_check -s exit:1 -e match:"agent.headers_file" ${OC} check
	chmod 0600 up.headers
	atf_check -o ignore ${OC} fluentbit
	rm up.headers
	atf_check -s exit:1 -e match:"does not exist" ${OC} fluentbit
	cat > local.conf <<EOF
enable = false;
agent { upstream = "http://c:4318"; }
EOF
	atf_check -s exit:3 -e match:"disabled" ${OC} fluentbit
	echo 'agent { upstream = 1; }' > local.conf
	atf_check -s exit:1 -e match:"agent.upstream must be" ${OC} fluentbit
}

atf_init_test_cases()
{
	atf_add_test_case shipped_files
	atf_add_test_case check_states
	atf_add_test_case show_redacts
	atf_add_test_case get_keys
	atf_add_test_case usage_errors
	atf_add_test_case fluentbit_render
	atf_add_test_case fluentbit_output
	atf_add_test_case fluentbit_chown
	atf_add_test_case fluentbit_faults
}
