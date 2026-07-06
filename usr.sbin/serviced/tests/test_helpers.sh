#
# SPDX-License-Identifier: BSD-2-Clause
#
# Common test helpers shared across serviced test suites.
#

daemon_pid=
pidfile=
conffile=
sockpath=
logfile=
serviced_bin=

find_serviced()
{
	local p
	local _m _p
	# obj dir is ${MACHINE}.${MACHINE_ARCH}: uname -m / uname -p (they
	# differ on e.g. arm64/aarch64), not uname -p twice.
	_m=$(uname -m)
	_p=$(uname -p)
	for p in \
	    "$(command -v serviced 2>/dev/null)" \
	    /usr/libexec/serviced \
	    /usr/obj/usr/src/${_m}.${_p}/usr.sbin/serviced/serviced
	do
		if [ -n "$p" ] && [ -x "$p" ]; then
			serviced_bin="$p"
			return
		fi
	done
	atf_skip "serviced binary not found"
}

prepare_paths()
{
	pidfile="$(pwd)/oracled.pid"
	conffile="$(pwd)/oracled.conf"
	sockpath="$(pwd)/oracled.sock"
	logfile="$(pwd)/oracled.log"
	mkdir -p "${APPS_DIR}" "${USER_APPS_DIR}"
}

write_config()
{
	find_serviced
	cat > "$conffile" <<EOF
pidfile = "$pidfile";
control_socket = "$sockpath";
control_socket_mode = "0700";
service_manager = "$serviced_bin";
serviced_control_socket = "${CTL_SOCK}";
EOF
	# Export bundle directory overrides so serviced scans test-local paths.
	export SERVICED_BUNDLE_DIR_SYSTEM="${APPS_DIR}"
	export SERVICED_BUNDLE_DIR_USER="${USER_APPS_DIR}"
}

start_stack()
{
	require_mac_capability
	prepare_paths
	write_config

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	daemon_pid=$!

	# Wait for oracled control socket.
	i=0
	while [ ! -S "$sockpath" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -S "$sockpath" ]; then
		cat "$logfile" 2>/dev/null
		atf_fail "oracled did not create control socket"
	fi

	# Wait for serviced to be ready (check oracle status).
	i=0
	while ! grep -q "serviced ready" "$logfile" 2>/dev/null && [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
}

wait_for_file()
{
	local path max i
	path="$1"
	max=$(( ${2:-15} * 10 ))
	i=0
	while [ ! -s "$path" ] && [ "$i" -lt "$max" ]; do
		i=$((i + 1))
		sleep 0.1
	done
	test -s "$path"
}

stop_stack()
{
	if [ -n "$daemon_pid" ]; then
		kill -TERM "$daemon_pid" 2>/dev/null || true
		wait "$daemon_pid" 2>/dev/null || true
	fi
}

cleanup_common()
{
	stop_stack
	pkill -9 -f "${serviced_bin:-/usr/libexec/serviced}" 2>/dev/null || true
	sleep 0.2
	rm -rf oracled.pid oracled.conf oracled.sock \
	    serviced.sock oracled.log lookup-name *.out *.pid *.sh *.c \
	    provider_svc client_svc ready_svc squat_svc \
	    lookup_client lookup_client.build.log ready_svc.build.log \
	    *.target *.result *.ready
}

write_executable()
{
	local path
	path="$1"
	shift
	printf "%s\n" "$@" > "$path"
	chmod +x "$path"
}

require_cc()
{
	if ! command -v cc >/dev/null 2>&1; then
		atf_skip "cc not available"
	fi
}

# Genuine environment precondition: the mac_capability device must be
# present for serviced to set up per-service channels and mint tokens.
# This is a legitimate "feature not available in this environment" skip
# (kept as atf_skip); "service did not start" once the device IS present
# is a real regression and must be an atf_fail.
require_mac_capability()
{
	if [ ! -c /dev/mac_capability ]; then
		atf_skip "mac_capability device not available"
	fi
}

libservice_path=

find_libservice()
{
	local p _m _p
	_m=$(uname -m)
	_p=$(uname -p)
	for p in \
	    /usr/lib/libservice.so \
	    /usr/obj/usr/src/${_m}.${_p}/lib/libservice/libservice.so.1
	do
		if [ -n "$p" ] && [ -f "$p" ]; then
			libservice_path="$(dirname "$p")"
			return
		fi
	done
	atf_skip "libservice not found"
}

cc_with_libservice()
{
	require_cc
	find_libservice
	cc -Wall -Wextra \
	    -I/usr/src/lib/libservice \
	    -L"$libservice_path" -lservice \
	    "$@"
}

# --- Bundle test helpers ---

export WORK="$(pwd)"
APPS_DIR="${WORK}/Capabilities/System"
USER_APPS_DIR="${WORK}/Capabilities"
CTL_SOCK="${WORK}/serviced.sock"

# Build ./ready_svc, a libservice service program that reports readiness so the
# service actually reaches SVC_STATE_RUNNING (the only promotion path is the
# SVC_OP_READY message handled in svc_proto.c — a plain /bin/sh script that just
# sleeps stays STARTING forever, so any "status ... running" assertion against a
# shell service can never match).
#
# Behaviour: register + report ready FIRST (so serviced observes RUNNING), then
# write "<name>.ready" in the CWD (the test work dir — oracled runs foreground
# so services inherit WORK as their CWD), then block.  The 200ms pause after
# service_ready() closes the race where the ready file appears before serviced
# has processed the READY message and flipped the service to RUNNING.
#
# The ready-file basename is argv[1] when supplied, else basename(argv[0]) — so a
# bundle installing this as bin/<prog> produces "<prog>.ready", matching what the
# tests wait_for_file on.
build_ready_svc()
{
	[ -x ./ready_svc ] && return 0
	require_cc
	find_libservice
	cat > ready_svc.c <<'CEOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>

int
main(int argc, char **argv)
{
	const char *name;
	char path[256];
	FILE *f;

	/* Reach RUNNING before advertising readiness to the test. */
	if (service_init() == 0)
		(void)service_ready();

	/* Give serviced a moment to process SVC_OP_READY (STARTING->RUNNING)
	 * before the ready file — several tests check status with no sleep. */
	usleep(200000);

	if (argc > 1 && argv[1][0] != '\0') {
		name = argv[1];
	} else {
		name = strrchr(argv[0], '/');
		name = (name != NULL) ? name + 1 : argv[0];
	}
	(void)snprintf(path, sizeof(path), "%s.ready", name);
	f = fopen(path, "w");
	if (f != NULL) {
		fprintf(f, "ready\n");
		fclose(f);
	}

	pause();
	return (0);
}
CEOF
	if ! cc_with_libservice -o ready_svc ready_svc.c \
	    >ready_svc.build.log 2>&1; then
		cat ready_svc.build.log >&2
		atf_fail "failed to build ready_svc"
	fi
}

# Create a system bundle (.cap) in the fake /Capabilities/System.
# Usage: create_system_bundle <name> <bundle_id> <program> <provides> [ucl_extra]
create_system_bundle()
{
	local name="$1" bid="$2" prog="$3" provides="$4" extra="${5:-}"
	local dir="${APPS_DIR}/${name}.cap"

	mkdir -p "${dir}/etc"
	mkdir -p "${dir}/bin"

	# Install the libservice ready-reporting helper as the program so the
	# service reaches RUNNING (a plain shell script never reports ready and
	# stays STARTING — see build_ready_svc).  It writes "<prog>.ready" in
	# its CWD (= WORK), which the tests wait_for_file on.
	build_ready_svc
	cp ready_svc "${dir}/bin/${prog}"
	chmod 755 "${dir}/bin/${prog}"

	cat > "${dir}/etc/${prog}.ucl" <<-UCL
	bundle_id = "${bid}";
	version = "1.0";
	author = "test";
	program = "${prog}";
	provides = ["${provides}"];
	${extra}
	UCL

	echo "${dir}"
}

# Create a system bundle with requires.
create_system_bundle_with_requires()
{
	local name="$1" bid="$2" prog="$3" provides="$4" requires="$5"
	create_system_bundle "$name" "$bid" "$prog" "$provides" \
	    "requires = [\"${requires}\"];"
}

# Create a user bundle (.cap) in the fake /Capabilities.
# Usage: create_user_bundle <name> <bundle_id> <program> <provides> [ucl_extra]
create_user_bundle()
{
	local name="$1" bid="$2" prog="$3" provides="$4" extra="${5:-}"
	local dir="${USER_APPS_DIR}/${name}.cap"

	mkdir -p "${dir}/etc"
	mkdir -p "${dir}/bin"

	# Install the libservice ready-reporting helper (see create_system_bundle
	# and build_ready_svc) so the service reaches RUNNING.
	build_ready_svc
	cp ready_svc "${dir}/bin/${prog}"
	chmod 755 "${dir}/bin/${prog}"

	cat > "${dir}/etc/${prog}.ucl" <<-UCL
	bundle_id = "${bid}";
	version = "1.0";
	author = "test";
	program = "${prog}";
	provides = ["${provides}"];
	${extra}
	UCL

	echo "${dir}"
}

# Create a user bundle with custom UCL content (full file).
create_user_bundle_custom()
{
	local name="$1" prog="$2" ucl_content="$3"
	local dir="${USER_APPS_DIR}/${name}.cap"

	mkdir -p "${dir}/etc"
	mkdir -p "${dir}/bin"

	printf '#!/bin/sh\nexec sleep 3600\n' > "${dir}/bin/${prog}"
	chmod 755 "${dir}/bin/${prog}"

	printf '%s\n' "${ucl_content}" > \
	    "${dir}/etc/${prog}.ucl"

	echo "${dir}"
}

# Create a single-service .cap bundle, migrating the legacy flat-manifest
# model (the /etc/serviced.d UCL manifest dir removed in 7311c2d).  serviced
# now only loads .cap bundles from the SERVICED_BUNDLE_DIR_* trees.
#
# The service label is provides[0] (see libcapbundle_parse.c), so passing the
# old manifest's `label` as the provides name keeps every "service <label>:"
# log assertion matching.
#
# Usage: make_svc <system|user> <label> <ucl_extra> <body-line>...
#   <ucl_extra>  extra manifest fields as a UCL fragment, e.g.
#                'restart = "never";' or 'user = "nobody"; stop_timeout = 2;'
#                (may be empty "").
#   <body-line>  one or more lines of the service script.  IMPORTANT: expand
#                ${WORK} at CALL time (double-quote the arg) so an absolute
#                path bakes into the script — services run with a minimal env
#                and do NOT inherit WORK.  Escape runtime shell vars (e.g. \$\$).
make_svc()
{
	local scope="$1" label="$2" extra="$3"
	local base dir
	shift 3
	if [ "$scope" = system ]; then
		base="${APPS_DIR}"
	else
		base="${USER_APPS_DIR}"
	fi
	dir="${base}/${label}.cap"
	mkdir -p "${dir}/etc" "${dir}/bin"
	printf '%s\n' "$@" > "${dir}/bin/${label}"
	chmod 755 "${dir}/bin/${label}"
	cat > "${dir}/etc/${label}.ucl" <<-UCL
	bundle_id = "org.test.${label}";
	version = "1.0";
	author = "test";
	program = "${label}";
	provides = ["${label}"];
	${extra}
	UCL
	echo "${dir}"
}

# Like make_svc, but installs a pre-built <binary> (e.g. a cc-compiled
# helper) as the service program instead of an inline shell script.
#
# Usage: make_svc_bin <system|user> <label> <ucl_extra> <binary-path>
make_svc_bin()
{
	local scope="$1" label="$2" extra="$3" bin="$4"
	local base dir
	if [ "$scope" = system ]; then
		base="${APPS_DIR}"
	else
		base="${USER_APPS_DIR}"
	fi
	dir="${base}/${label}.cap"
	mkdir -p "${dir}/etc" "${dir}/bin"
	cp "$bin" "${dir}/bin/${label}"
	chmod 755 "${dir}/bin/${label}"
	cat > "${dir}/etc/${label}.ucl" <<-UCL
	bundle_id = "org.test.${label}";
	version = "1.0";
	author = "test";
	program = "${label}";
	provides = ["${label}"];
	${extra}
	UCL
	echo "${dir}"
}

# Build ./lookup_client, a libservice-based service program that performs a
# single service_lookup() and records the result.
#
# A lookup that can trigger an on-demand launch MUST arrive over a real
# service channel (serviced only launches on-demand services in response to a
# SVC_OP_LOOKUP from a managed service).  A standalone `./lookup_client name`
# has no ORACLED_CHANNEL_FD, so the client is instead installed and run as a
# managed service (see run_lookup_client below).
#
# The program discovers its own label from ORACLED_LABEL (serviced always sets
# it), reads the target name from "<label>.target" in its CWD (the test work
# dir — serviced does not chdir), and writes "<label>.result" with rc=0 on a
# successful lookup or rc=1 on failure.  Using the label for the file names
# keeps concurrent lookups (each a distinct bundle) from colliding.
build_lookup_client()
{
	[ -x ./lookup_client ] && return 0
	require_cc
	find_libservice
	cat > lookup_client.c <<'CEOF'
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libservice.h>

int
main(int argc, char **argv)
{
	char tfile[256], rfile[256], target[256];
	const char *label;
	FILE *f;
	int fd, rc;

	label = getenv("ORACLED_LABEL");
	if (label == NULL || label[0] == '\0')
		label = "lookup_client";
	(void)snprintf(tfile, sizeof(tfile), "%s.target", label);
	(void)snprintf(rfile, sizeof(rfile), "%s.result", label);

	/* Target name: file first, then argv[1] as a fallback. */
	target[0] = '\0';
	f = fopen(tfile, "r");
	if (f != NULL) {
		if (fgets(target, sizeof(target), f) != NULL) {
			size_t l = strlen(target);
			if (l > 0 && target[l - 1] == '\n')
				target[l - 1] = '\0';
		}
		fclose(f);
	}
	if (target[0] == '\0' && argc > 1)
		(void)strlcpy(target, argv[1], sizeof(target));

	rc = 1;
	fd = -1;
	if (service_init() == 0 && service_ready() == 0) {
		fd = service_lookup(target);
		if (fd != -1)
			rc = 0;
	}

	f = fopen(rfile, "w");
	if (f != NULL) {
		fprintf(f, "fd=%d\nerrno=%d\nrc=%d\n", fd, errno, rc);
		fclose(f);
	}
	return (rc);
}
CEOF
	if ! cc_with_libservice -o lookup_client lookup_client.c \
	    >lookup_client.build.log 2>&1; then
		cat lookup_client.build.log >&2
		atf_fail "failed to build lookup_client"
	fi
}

# Trigger a lookup of <name> from a managed client service and wait for the
# result, returning 0 if the lookup succeeded and 1 otherwise (including
# timeout).  Prints nothing on stdout so it can be wrapped in atf_check.
#
# Usage: run_lookup_client <name> [timeout_seconds]
run_lookup_client()
{
	local name="$1" timeout="${2:-5}"
	local label result i max

	build_lookup_client

	# Unique per-invocation label so concurrent lookups don't collide.
	label=$(basename "$(mktemp -u lookupcli.XXXXXX)")
	result="${label}.result"
	rm -f "$result"
	printf '%s\n' "$name" > "${label}.target"

	# Install the client as a boot-start service (runs once) and ask
	# serviced to pick up the new bundle.
	make_svc_bin user "$label" 'restart = "never";' \
	    "$(pwd)/lookup_client" >/dev/null
	kill -HUP "$daemon_pid" 2>/dev/null || true

	# Wait for the client to record its lookup result.
	max=$(( timeout * 10 ))
	i=0
	while [ ! -s "$result" ] && [ "$i" -lt "$max" ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -s "$result" ]; then
		return 1
	fi
	grep -q '^rc=0$' "$result"
}

# Start the stack expecting it to fail (for negative tests).
start_stack_expect_failure()
{
	require_mac_capability
	prepare_paths
	write_config

	oracled -d -f "$conffile" >"$logfile" 2>&1 &
	local pid=$!
	sleep 1
	# If it's still running, it didn't fail as expected
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null
		return 1
	fi
	return 0
}
