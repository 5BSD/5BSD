#
# SPDX-License-Identifier: BSD-2-Clause
#
# Common test helpers shared across serviced test suites.
#

. "$(atf_get_srcdir)/capd_test_harness.sh"

daemon_pid=
pidfile=
conffile=
sockpath=
logfile=
serviced_bin=

find_serviced()
{
	capd_find_serviced
	serviced_bin=$capd_serviced_bin
}

prepare_paths()
{
	capd_paths_init
	pidfile=$CAPD_PIDFILE
	conffile=$CAPD_CONFIG
	sockpath=$CAPD_AUTHORITY_SOCKET
	logfile=$CAPD_LOG
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
	# Fixture serviced must never replay the host's /etc/rc.
	export SERVICED_SKIP_RC=1
}

start_stack()
{
	prepare_paths
	if [ ! -r "$conffile" ]; then
		write_config
	fi
	capd_start_stack
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')
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

wait_for_log()
{
	local i pattern

	pattern=$1
	i=0
	while ! grep -Eq "$pattern" "$logfile" 2>/dev/null &&
	    [ "$i" -lt 150 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	grep -Eq "$pattern" "$logfile" 2>/dev/null
}

reload_stack()
{
	if [ ! -S "$sockpath" ]; then
		atf_fail "Authority control socket is unavailable for reload"
	fi
	atf_check -s exit:0 -o ignore \
	    authorityctl -s "$sockpath" reload
}

stop_stack()
{
	local i result target

	prepare_paths
	capd_find_guardian
	if [ -S "$CAPD_GUARDIAN_SOCKET" ] || [ -n "$capd_guardian_pid" ]; then
		capd_stop_stack
		result=$?
		daemon_pid=
		return "$result"
	fi

	# Transitional path for cases not yet launched through the guardian.
	target=$daemon_pid
	if [ -z "$target" ] && [ -r "$pidfile" ]; then
		read -r target <"$pidfile" || target=
	fi
	if [ -S "$sockpath" ]; then
		authorityctl -s "$sockpath" shutdown >/dev/null 2>&1 || true
	fi
	case "$target" in
	''|*[!0-9]*) return 0 ;;
	esac
	i=0
	while ps -p "$target" -o pid= 2>/dev/null | grep -q '[0-9]' &&
	    [ "$i" -lt 350 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	daemon_pid=
	if ps -p "$target" -o pid= 2>/dev/null | grep -q '[0-9]'; then
		echo "test cleanup: Authority $target did not exit" >&2
		return 1
	fi
	return 0
}

cleanup_common()
{
	local cleanup_status

	cleanup_status=0
	# The body process owned the guardian lease.  ATF cleanup runs in a new
	# process, after lease closure may already have initiated fail-safe stack
	# termination.  Do not turn that expected race into a broken test; judge
	# cleanup by whether the recovery pass removes the complete stack.
	stop_stack || true
	capd_cleanup_stack || cleanup_status=1
	sleep 0.2
	rm -rf authorityd.pid authorityd.conf authorityd.sock \
	    serviced.sock authorityd.log lookup-name *.out *.pid *.sh *.c \
	    provider_svc client_svc ready_svc squat_svc \
	    lookup_client lookup_client.build.log ready_svc.build.log \
	    *.target *.result *.ready
	return "$cleanup_status"
}

write_executable()
{
	local path
	path="$1"
	shift
	printf "%s\n" "$@" > "$path"
	chmod +x "$path"
}

# Every test that launches Authority also exercises its mandatory capability
# services, even when the test itself is concerned with only one of them.
# Declare the complete baseline in the test head so Kyua can load modules
# before entering the body.  Additional capability-service modules may be
# supplied by callers as positional arguments.
require_authority_stack_kmods()
{
	capd_require_stack_kmods "$@"
}

# Genuine environment precondition: the mac_capability device must be
# present for serviced to set up per-service channels and mint tokens.
# This is a legitimate "feature not available in this environment" skip
# (kept as atf_skip); "service did not start" once the device IS present
# is a real regression and must be an atf_fail.
require_mac_capability()
{
	capd_require_device
}

capd_service_fixture=

find_capd_service_fixture()
{
	local candidate srcdir

	if [ -n "$capd_service_fixture" ] && [ -x "$capd_service_fixture" ]; then
		return 0
	fi
	srcdir=$(atf_get_srcdir)
	for candidate in \
	    "${CAPD_SERVICE_FIXTURE:-}" \
	    "${srcdir}/capd_service_fixture" \
	    "$(command -v capd_service_fixture 2>/dev/null)"
	do
		if [ -n "$candidate" ] && [ -x "$candidate" ]; then
			capd_service_fixture=$candidate
			return 0
		fi
	done
	atf_fail "capd_service_fixture is unavailable"
}

# --- Bundle test helpers ---

export WORK="$(pwd)"
APPS_DIR="${WORK}/Capabilities/System"
USER_APPS_DIR="${WORK}/Capabilities"
CTL_SOCK="${WORK}/serviced.sock"

normalize_test_unit_extra()
{
	printf '%s\n' "$1"
}

write_test_bundle()
{
	local dir="$1" bid="$2" prog="$3" extra="$4" activation="$5"
	local normalized

	mkdir -p "$dir/Units/$prog.unit/bin"
	cat > "$dir/Bundle.ucl" <<-UCL
	schema = "org.5bsd.capability-bundle";
	schema_version = 1;
	bundle_id = "${bid}";
	version = "1.0.0";
	sequence = 1;
	author = "test";
	publisher = "org.test";
	units = ["${prog}"];
	UCL
	normalized=$(normalize_test_unit_extra "$extra")
	case "$normalized" in
	*"activation "*) ;;
	*) normalized="${activation}
${normalized}" ;;
	esac
	printf '%s\n' "$normalized" > "$dir/Units/$prog.unit/Unit.ucl"
}

# Build ./ready_svc, a libservice service program that enters capability mode
# through service_ready(), allowing serviced to verify NOTE_CAPMODE and promote
# it to SVC_STATE_RUNNING.  A plain /bin/sh script that sleeps never crosses
# that boundary and therefore remains STARTING.
#
# Behaviour: enter the sandbox and report ready, then
# write "<name>.ready" in the CWD (the test work dir — authorityd runs foreground
# so services inherit WORK as their CWD), then block.  The fixture pre-opens
# that directory, so marker creation remains descriptor-relative after
# cap_enter().  The 200ms pause closes the race where the marker appears before
# serviced has processed NOTE_CAPMODE and flipped the service to RUNNING.
#
# The ready-file basename is argv[1] when supplied, else basename(argv[0]) — so a
# bundle installing this as bin/<prog> produces "<prog>.ready", matching what the
# tests wait_for_file on.
build_ready_svc()
{
	[ -x ./ready_svc ] && return 0
	find_capd_service_fixture
	cp "$capd_service_fixture" ready_svc
	chmod 0555 ready_svc
}

# Create a system bundle (.cap) in the fake /Capabilities/System.
# Usage: create_system_bundle <name> <bundle_id> <program> <provides> [ucl_extra]
create_system_bundle()
{
	local name="$1" bid="$2" prog="$3" provides="$4" extra="${5:-}"
	local dir="${APPS_DIR}/${name}.cap"

	write_test_bundle "$dir" "$bid" "$prog" "$extra" \
	    "activation { boot = true; ipc = [\"${provides}\"]; }"

	# Install the libservice ready-reporting helper as the program so the
	# service reaches RUNNING (a plain shell script never reports ready and
	# stays STARTING — see build_ready_svc).  It writes "<prog>.ready" in
	# its CWD (= WORK), which the tests wait_for_file on.
	build_ready_svc
	cp ready_svc "${dir}/Units/${prog}.unit/bin/${prog}"
	chmod 755 "${dir}/Units/${prog}.unit/bin/${prog}"
	printf '%s\n' "arguments = [\"compat-ready\", \"${provides}\"];" >> \
	    "$dir/Units/$prog.unit/Unit.ucl"

	echo "${dir}"
}

# Create a user bundle (.cap) in the fake /Capabilities.
# Usage: create_user_bundle <name> <bundle_id> <program> <provides> [ucl_extra]
create_user_bundle()
{
	local name="$1" bid="$2" prog="$3" provides="$4" extra="${5:-}"
	local dir="${USER_APPS_DIR}/${name}.cap"

	write_test_bundle "$dir" "$bid" "$prog" "$extra" \
	    "activation { ipc = [\"${provides}\"]; }"

	# Install the libservice ready-reporting helper (see create_system_bundle
	# and build_ready_svc) so the service reaches RUNNING.
	build_ready_svc
	cp ready_svc "${dir}/Units/${prog}.unit/bin/${prog}"
	chmod 755 "${dir}/Units/${prog}.unit/bin/${prog}"
	printf '%s\n' "arguments = [\"compat-ready\", \"${provides}\"];" >> \
	    "$dir/Units/$prog.unit/Unit.ucl"

	echo "${dir}"
}

# Create a user bundle with custom UCL content (full file).
create_user_bundle_custom()
{
	local name="$1" prog="$2" ucl_content="$3"
	local dir="${USER_APPS_DIR}/${name}.cap"

	# The custom helper is demand-activated and derives identity from name.
	write_test_bundle "$dir" "org.test.${name}" "$prog" "$ucl_content" \
	    'activation { boot = true; }'

	printf '#!/bin/sh\nexec sleep 3600\n' > \
	    "$dir/Units/$prog.unit/bin/$prog"
	chmod 755 "$dir/Units/$prog.unit/bin/$prog"

	echo "${dir}"
}

# Create a single-unit .cap bundle in a test registry.
#
# Runtime identity is explicit and independent from provides[].
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
	local base bid dir unit
	shift 3
	if [ "$scope" = system ]; then
		base="${APPS_DIR}"
	else
		base="${USER_APPS_DIR}"
	fi
	case "$label" in
	*.*)
		# A dotted label is a complete bundle id; the unit takes the
		# last component.  Splitting the id off the label collides
		# distinct bundles onto one bundle_id.
		bid=$label
		unit=${label##*.}
		;;
	*)
		bid="org.test.${label}"
		unit=$label
		;;
	esac
	dir="${base}/${label}.cap"
	write_test_bundle "$dir" "$bid" "$unit" "$extra" \
	    'activation { boot = true; }'
	printf '%s\n' "$@" > "$dir/Units/$unit.unit/bin/$unit"
	chmod 755 "$dir/Units/$unit.unit/bin/$unit"
	echo "${dir}"
}

# Like make_svc, but installs a pre-built <binary> (e.g. a cc-compiled
# helper) as the service program instead of an inline shell script.
#
# Usage: make_svc_bin <system|user> <label> <ucl_extra> <binary-path>
make_svc_bin()
{
	local scope="$1" label="$2" extra="$3" bin="$4"
	local base bid dir unit
	if [ "$scope" = system ]; then
		base="${APPS_DIR}"
	else
		base="${USER_APPS_DIR}"
	fi
	case "$label" in
	*.*)
		# A dotted label is a complete bundle id; the unit takes the
		# last component.  Splitting the id off the label collides
		# distinct bundles onto one bundle_id.
		bid=$label
		unit=${label##*.}
		;;
	*)
		bid="org.test.${label}"
		unit=$label
		;;
	esac
	dir="${base}/${label}.cap"
	write_test_bundle "$dir" "$bid" "$unit" "$extra" \
	    'activation { boot = true; }'
	cp "$bin" "$dir/Units/$unit.unit/bin/$unit"
	chmod 755 "$dir/Units/$unit.unit/bin/$unit"
	echo "${dir}"
}

# Build ./lookup_client, a libservice-based service program that performs a
# single service_lookup() and records the result.
#
# A lookup that can trigger an on-demand launch MUST arrive over a real
# service channel (serviced only launches on-demand services in response to a
# SVC_OP_LOOKUP from a managed service).  A standalone `./lookup_client name`
# has no serviced bootstrap descriptor, so the client is instead run as a
# managed service (see run_lookup_client below).
#
# The program discovers its own label through libservice, reads the target
# name from "<label>.target" in its CWD (the test work
# dir — serviced does not chdir), and writes "<label>.result" with rc=0 on a
# successful lookup or rc=1 on failure.  Using the label for the file names
# keeps concurrent lookups (each a distinct bundle) from colliding.
build_lookup_client()
{
	[ -x ./lookup_client ] && return 0
	find_capd_service_fixture
	cp "$capd_service_fixture" lookup_client
	chmod 0555 lookup_client
}

# Trigger a lookup of <name> from a managed client service and wait for the
# result, returning 0 if the lookup succeeded and 1 otherwise (including
# timeout).  Prints nothing on stdout so it can be wrapped in atf_check.
#
# Usage: run_lookup_client <name> [timeout_seconds]
run_lookup_client()
{
	local name="$1" timeout="${2:-5}"
	local bundle label result i max

	build_lookup_client

	# Unique per-invocation label so concurrent lookups don't collide.
	# The bundle id needs a dot and the runtime label is bundle/unit; the
	# fixture flattens '/' to '.' when deriving its marker file names.
	label="org.test.$(basename "$(mktemp -u lookupcli-XXXXXX)" | tr 'A-Z' 'a-z')"
	unit=${label##*.}
	result="${label}.${unit}.result"
	rm -f "$result"
	printf '%s\n' "$name" > "${label}.${unit}.target"

	# Install the client as a boot-start service (runs once) and ask
	# serviced to pick up the new bundle.
	bundle=$(make_svc_bin user "$label" \
	    'restart = "never"; arguments = ["compat-lookup"];' \
	    "$(pwd)/lookup_client")
	reload_stack

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
	local i

	require_mac_capability
	prepare_paths
	write_config
	capd_find_guardian
	capd_launch_authority
	daemon_pid=$("$capd_guardian_bin" ctl -s "$CAPD_GUARDIAN_SOCKET" status |
	    sed -n 's/^running pid=//p')
	i=0
	while ! grep -Eq 'serviced ready|cycle detected|dependency sort failed|serviced exited' \
	    "$logfile" 2>/dev/null && [ "$i" -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	# Authority is allowed to remain healthy and supervise restart attempts; the
	# contract under test is that serviced never reports ready with an invalid
	# registry.  Always use the authenticated shutdown path for cleanup.
	if grep -q "serviced ready" "$logfile" 2>/dev/null; then
		stop_stack
		return 1
	fi
	stop_stack
	return 0
}
