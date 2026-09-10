#!/bin/sh
#
# Run the focused Capsule/switchboard capability suite under Kyua.  Kyua owns
# test isolation, timeout enforcement, cleanup phases, and result reporting.
#

set -u

usage()
{
	cat <<EOF
usage: $(basename "$0") [-o objtop] [-r results-directory]

Run as root.  From a source tree, objtop defaults to its native /usr/obj
path and the runner links temporary static tools from that coherent object
tree.  An installed copy uses the packaged programs, libraries, and tests;
-o selects a development object tree explicitly.  The Kyua database, log,
staged suite, and report are retained; temporary static tools are removed.
EOF
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
srcroot=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
machine=$(uname -m)
machine_arch=$(uname -p)
objtop="/usr/obj${srcroot}/${machine}.${machine_arch}"
objtop_set=0
results=

while getopts "o:r:h" opt; do
	case "$opt" in
	o)	objtop=$OPTARG
		objtop_set=1 ;;
	r)	results=$OPTARG ;;
	h)	usage
		exit 0 ;;
	*)	usage >&2
		exit 64 ;;
	esac
done
shift $((OPTIND - 1))

if [ "$#" -ne 0 ]; then
	usage >&2
	exit 64
fi
if [ "$(id -u)" -ne 0 ]; then
	echo "error: this suite must be run as root" >&2
	exit 77
fi

list_daemons()
{
	ps -axww -o pid= -o command= | awk '
		{
			name = $2
			sub(/^.*\//, "", name)
			if (name == "capsule" || name == "switchboard") {
				found = 1
				print
			}
		}
		END { exit !found }
	'
}

if list_daemons; then
	echo "error: stop the existing daemons before running this suite" >&2
	exit 69
fi
if ! command -v kyua >/dev/null 2>&1; then
	echo "error: kyua is required" >&2
	exit 69
fi

if [ -z "$results" ]; then
	results=$(mktemp -d /tmp/capsule-switchboard-root.XXXXXX) || exit 1
else
	mkdir -p "$results" || exit 1
	results=$(CDPATH= cd -- "$results" && pwd)
fi

development_mode=0
if [ "$objtop_set" -eq 0 ] && [ ! -f "$srcroot/Makefile.inc1" ]; then
	capsule_dir=/usr/sbin
	capsulectl_dir=/usr/sbin
	switchboard_dir=/usr/libexec
	switchboardctl_dir=/usr/sbin
	switchboard_test_dir=/usr/tests/usr.sbin/switchboard
	capsule_test_dir=/usr/tests/usr.sbin/capsule
	capsulert_dir=/usr/lib
	service_lib_dir=/usr/lib
	service_test_dir=/usr/tests/lib/libservice
	capbundle_lib_dir=/usr/lib
	capability_lib_dir=/usr/lib
	mac_test_dir=/usr/tests/sys/mac_capability
	capbundle_test_dir=/usr/tests/lib/libcapbundle
	capability_test_dir=/usr/tests/lib/libcapability
	capsulert_test_dir=/usr/tests/lib/libcapsulert
else
	development_mode=1
	capsule_dir="$objtop/usr.sbin/capsule"
	capsulectl_dir="$objtop/usr.sbin/capsulectl"
	switchboard_dir="$objtop/usr.sbin/switchboard"
	switchboardctl_dir="$objtop/usr.sbin/switchboardctl"
	switchboard_test_dir="$objtop/usr.sbin/switchboard/tests"
	capsule_test_dir="$objtop/usr.sbin/capsule/tests"
	capsulert_dir="$objtop/lib/libcapsulert"
	service_lib_dir="$objtop/lib/libservice"
	service_test_dir="$objtop/lib/libservice/tests"
	capbundle_lib_dir="$objtop/lib/libcapbundle"
	capability_lib_dir="$objtop/lib/libcapability"
	mac_test_dir="$objtop/tests/sys/mac_capability"
	capbundle_test_dir="$objtop/lib/libcapbundle/tests"
	capability_test_dir="$objtop/lib/libcapability/tests"
	capsulert_test_dir="$objtop/lib/libcapsulert/tests"
fi

if [ "$development_mode" -eq 1 ]; then
	harness_source="$srcroot/usr.sbin/capsule/tests/capd_test_harness.sh"
else
	harness_source="$service_test_dir/capd_test_harness.sh"
fi

claim_parse_prog="$capsulert_test_dir/claim_parse_test"
req_validate_prog="$capsule_test_dir/req_validate_test"
guardian_prog="$capsule_test_dir/capd_test_guardian"
bootstrap_fixture_prog="$capsule_test_dir/capd_bootstrap_fixture"
service_fixture_prog="$service_test_dir/capd_service_fixture"
service_api_prog="$service_test_dir/libservice_api_test"

for executable in \
	"$capsule_dir/capsule" \
	"$capsulectl_dir/capsulectl" \
	"$switchboard_dir/switchboard" \
	"$switchboardctl_dir/switchboardctl" \
	"$switchboard_test_dir/switchboard_integration_test" \
	"$switchboard_test_dir/bundle_integration_test" \
	"$capbundle_test_dir/libcapbundle_test" \
	"$capability_test_dir/libcapability_test" \
	"$capsulert_test_dir/claim_parse_test" \
	"$service_test_dir/libservice_test" \
	"$service_test_dir/capd_service_fixture" \
	"$service_test_dir/libservice_api_test" \
	"$capsule_test_dir/capsule_bootstrap_test" \
	"$capsule_test_dir/capd_bootstrap_fixture" \
	"$capsule_test_dir/capd_test_guardian" \
	"$capsule_test_dir/capd_test_guardian_test" \
	"$capsule_test_dir/req_validate_test" \
	"$mac_test_dir/mac_capability_test" \
	"$mac_test_dir/mac_capability_isolation_test" \
	"$mac_test_dir/mac_capability_isolation_helper" \
	"$mac_test_dir/mac_capability_shield_helper"
do
	if [ ! -x "$executable" ]; then
		echo "error: required development binary not found: $executable" >&2
		echo "hint: build it or override the object root with -o objtop" >&2
		exit 66
	fi
done

for library in \
	"$service_lib_dir/libservice.so" \
	"$capbundle_lib_dir/libcapbundle.so" \
	"$capability_lib_dir/libcapability.so" \
	"$capsulert_dir/libcapsulert.so"
do
	if [ ! -r "$library" ]; then
		echo "error: required development library not found: $library" >&2
		echo "hint: build it or override the object root with -o objtop" >&2
		exit 66
	fi
done

# Fail before Kyua if a partially rebuilt object tree mixes a new consumer
# with an older libcapbundle ABI.  LD_LIBRARY_PATH alone cannot make such a
# tree coherent; reporting the exact rebuild is substantially more useful
# than an ld-elf.so.1 error buried in the first test case.
for symbol in \
	capbundle_svc_narguments \
	capbundle_svc_argument \
	capbundle_svc_nenvironment \
	capbundle_svc_environment
do
	if ! nm -D "$capbundle_lib_dir/libcapbundle.so" 2>/dev/null |
	    awk -v wanted="$symbol" '$3 == wanted { found = 1 }
	        END { exit !found }'; then
		echo "error: development libcapbundle is missing $symbol" >&2
		echo "hint: rebuild lib/libcapbundle and usr.sbin/switchboardctl together" >&2
		exit 65
	fi
done

if ! nm -D "$service_lib_dir/libservice.so" 2>/dev/null |
    awk '$3 == "service_capability_open" { found = 1 }
        END { exit !found }'; then
	echo "error: development libservice is missing service_capability_open" >&2
	echo "hint: rebuild lib/libservice and dependent service programs" >&2
	exit 65
fi

link_static_program()
{
	link_src=$1
	link_objdir=$2
	link_output=$3
	shift 3

	link_objs=$(make -C "$link_src" -V OBJS NO_SHARED=yes "$@") ||
	    return 1
	link_ldadd=$(make -C "$link_src" -V LDADD NO_SHARED=yes "$@") ||
	    return 1
	link_resolved=
	for link_obj in $link_objs; do
		link_pie=${link_obj%.o}.pieo
		if [ -f "$link_objdir/$link_pie" ]; then
			link_resolved="$link_resolved $link_pie"
		elif [ -f "$link_objdir/$link_obj" ]; then
			link_resolved="$link_resolved $link_obj"
		else
			echo "error: missing object for static test tool: $link_objdir/$link_obj" >&2
			return 1
		fi
	done
	(cd "$link_objdir" &&
	    cc -static -o "$link_output" $link_resolved $link_ldadd)
}

cleanup_static_tools()
{
	case "${static_tools_dir:-}" in
	"$objtop"/.capsule-switchboard-tools.*)
		rm -rf -- "$static_tools_dir"
		;;
	esac
}

if [ "$development_mode" -eq 1 ]; then
	# Root execution of user-owned object-tree binaries is tainted.  rtld then
	# ignores LD_LIBRARY_PATH and can silently bind a new consumer to stale
	# installed libraries.  Link coherent static tools from the already-built
	# objects and libraries.  Keep them on the object filesystem (not a nosuid
	# temporary filesystem) so MAC exec credential transitions remain active.
	static_tools_dir=$(mktemp -d "$objtop/.capsule-switchboard-tools.XXXXXX") ||
	    exit 1
	trap cleanup_static_tools EXIT
	trap 'exit 1' HUP INT TERM
	echo "Linking coherent static development tools"
	if ! link_static_program "$srcroot/usr.sbin/capsule" \
	    "$capsule_dir" "$static_tools_dir/capsule" ||
	    ! link_static_program "$srcroot/usr.sbin/capsulectl" \
	    "$capsulectl_dir" "$static_tools_dir/capsulectl" ||
	    ! link_static_program "$srcroot/usr.sbin/switchboard" \
	    "$switchboard_dir" "$static_tools_dir/switchboard" ||
	    ! link_static_program "$srcroot/usr.sbin/switchboardctl" \
	    "$switchboardctl_dir" "$static_tools_dir/switchboardctl" ||
	    ! link_static_program "$srcroot/lib/libcapsulert/tests" \
	    "$capsulert_test_dir" "$static_tools_dir/claim_parse_test" \
	    PROG=claim_parse_test ||
	    ! link_static_program "$srcroot/usr.sbin/capsule/tests" \
	    "$capsule_test_dir" "$static_tools_dir/req_validate_test" \
	    PROG=req_validate_test ||
	    ! link_static_program "$srcroot/usr.sbin/capsule/tests" \
	    "$capsule_test_dir" "$static_tools_dir/capd_test_guardian" \
	    PROG=capd_test_guardian ||
	    ! link_static_program "$srcroot/usr.sbin/capsule/tests" \
	    "$capsule_test_dir" "$static_tools_dir/capd_bootstrap_fixture" \
	    PROG=capd_bootstrap_fixture ||
	    ! link_static_program "$srcroot/lib/libservice/tests" \
	    "$service_test_dir" "$static_tools_dir/capd_service_fixture" \
	    PROG=capd_service_fixture ||
	    ! link_static_program "$srcroot/lib/libservice/tests" \
	    "$service_test_dir" "$static_tools_dir/libservice_api_test" \
	    PROG=libservice_api_test; then
		echo "error: failed to link coherent static development tools" >&2
		exit 65
	fi
	capsule_dir=$static_tools_dir
	capsulectl_dir=$static_tools_dir
	switchboard_dir=$static_tools_dir
	switchboardctl_dir=$static_tools_dir
	claim_parse_prog="$static_tools_dir/claim_parse_test"
	req_validate_prog="$static_tools_dir/req_validate_test"
	guardian_prog="$static_tools_dir/capd_test_guardian"
	bootstrap_fixture_prog="$static_tools_dir/capd_bootstrap_fixture"
	service_fixture_prog="$static_tools_dir/capd_service_fixture"
	service_api_prog="$static_tools_dir/libservice_api_test"
fi

PATH="$capsule_dir:$capsulectl_dir:$switchboard_dir:$switchboardctl_dir:$capsulert_dir:/usr/bin:/bin:/usr/sbin:/sbin"
LD_LIBRARY_PATH="$service_lib_dir:$capability_lib_dir:$capbundle_lib_dir:$capsulert_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH LD_LIBRARY_PATH

suite_dir="$results/suite"
mkdir -p "$suite_dir" || exit 1
install -m 0444 "$script_dir/CapabilityKyuafile" "$suite_dir/Kyuafile" || exit 1
install -m 0444 "$script_dir/test_helpers.sh" "$suite_dir/test_helpers.sh" || exit 1
install -m 0444 "$harness_source" \
	"$suite_dir/capd_test_harness.sh" || exit 1

stage_atf_shell()
{
	stage_source=$1
	stage_target=$2
	{
		echo '#! /usr/libexec/atf-sh'
		cat "$stage_source"
	} > "$stage_target" || return 1
	chmod 0555 "$stage_target"
}

# Development shell tests are staged from current source so test-only edits do
# not require rebuilding generated ATF wrappers.  Compiled test programs remain
# symlinked below: /tmp is commonly MNT_NOSUID, and executing their vnode on the
# object filesystem preserves MAC exec credential transitions.
if [ "$development_mode" -eq 1 ]; then
	stage_atf_shell "$script_dir/switchboard_integration_test.sh" \
	    "$suite_dir/switchboard_integration_test" || exit 1
	stage_atf_shell "$script_dir/bundle_integration_test.sh" \
	    "$suite_dir/bundle_integration_test" || exit 1
	stage_atf_shell "$srcroot/lib/libcapbundle/tests/libcapbundle_test.sh" \
	    "$suite_dir/libcapbundle_test" || exit 1
	stage_atf_shell "$srcroot/lib/libcapability/tests/libcapability_test.sh" \
	    "$suite_dir/libcapability_test" || exit 1
	stage_atf_shell "$srcroot/lib/libservice/tests/libservice_test.sh" \
	    "$suite_dir/libservice_test" || exit 1
	stage_atf_shell "$srcroot/usr.sbin/capsule/tests/capd_test_guardian_test.sh" \
	    "$suite_dir/capd_test_guardian_test" || exit 1
	stage_atf_shell "$srcroot/usr.sbin/capsule/tests/capsule_bootstrap_test.sh" \
	    "$suite_dir/capsule_bootstrap_test" || exit 1
else
	ln -s "$switchboard_test_dir/switchboard_integration_test" \
	    "$suite_dir/switchboard_integration_test" || exit 1
	ln -s "$switchboard_test_dir/bundle_integration_test" \
	    "$suite_dir/bundle_integration_test" || exit 1
	ln -s "$capbundle_test_dir/libcapbundle_test" \
	    "$suite_dir/libcapbundle_test" || exit 1
	ln -s "$capability_test_dir/libcapability_test" \
	    "$suite_dir/libcapability_test" || exit 1
	ln -s "$service_test_dir/libservice_test" \
	    "$suite_dir/libservice_test" || exit 1
	ln -s "$capsule_test_dir/capd_test_guardian_test" \
	    "$suite_dir/capd_test_guardian_test" || exit 1
	ln -s "$capsule_test_dir/capsule_bootstrap_test" \
	    "$suite_dir/capsule_bootstrap_test" || exit 1
fi
ln -s "$claim_parse_prog" \
	"$suite_dir/claim_parse_test" || exit 1
ln -s "$req_validate_prog" \
	"$suite_dir/req_validate_test" || exit 1
ln -s "$guardian_prog" \
	"$suite_dir/capd_test_guardian" || exit 1
ln -s "$bootstrap_fixture_prog" \
	"$suite_dir/capd_bootstrap_fixture" || exit 1
ln -s "$service_fixture_prog" \
	"$suite_dir/capd_service_fixture" || exit 1
ln -s "$service_api_prog" \
	"$suite_dir/libservice_api_test" || exit 1
ln -s "$mac_test_dir/mac_capability_test" \
	"$suite_dir/mac_capability_test" || exit 1
ln -s "$mac_test_dir/mac_capability_isolation_test" \
	"$suite_dir/mac_capability_isolation_test" || exit 1
ln -s "$mac_test_dir/mac_capability_isolation_helper" \
	"$suite_dir/mac_capability_isolation_helper" || exit 1
ln -s "$mac_test_dir/mac_capability_shield_helper" \
	"$suite_dir/mac_capability_shield_helper" || exit 1

echo "Running focused capability suite under Kyua"
echo "Results directory: $results"

run_kyua_case()
{
	case_label=$1
	case_selector=$2
	case_database="$results/$case_label.db"
	case_log="$results/$case_label.log"
	case_report="$results/$case_label.report.txt"

	printf '\n==> %s\n' "$case_selector"
	# The suite and its private staging directory are root-only.  Keep even
	# nominally unprivileged parser cases in that same execution context;
	# cases that exercise peer authorization perform their own explicit
	# credential transition.
	if kyua -c none -v unprivileged_user=root \
	    --logfile="$results/$case_label.kyua.log" test \
	    -k "$suite_dir/Kyuafile" -r "$case_database" \
	    "$case_selector" >"$case_log" 2>&1; then
		case_status=0
	else
		case_status=$?
	fi
	cat "$case_log"

	if [ -f "$case_database" ]; then
		kyua -c none report -r "$case_database" --verbose \
		    >"$case_report" 2>&1 || true
	fi

	# A skip means this focused verification did not prove its contract.
	if grep -Eq -- '->[[:space:]]+(skipped|broken|failed):' \
	    "$case_log"; then
		case_status=1
	fi
	if list_daemons; then
		echo "error: $case_selector left a daemon running" >&2
		case_status=1
	fi
	if [ "$case_status" -ne 0 ] && [ -s "$case_report" ]; then
		echo "Detailed Kyua report:" >&2
		cat "$case_report" >&2
	fi
	return "$case_status"
}

set -- \
	manifest_network_schema=libcapbundle_test:network_capabilities \
	manifest_file_schema=libcapbundle_test:file_capabilities \
	manifest_system_schema=libcapbundle_test:all_system_gates \
	manifest_exec_vsock_schema=libcapbundle_test:arguments_environment_and_vsock \
	manifest_malformed_matrix=libcapbundle_test:malformed_schema_matrix \
	manifest_symlink_rejected=libcapbundle_test:symlink_rejected \
	kernel_capability_boundary=libcapability_test:kernel_boundary \
	network_name_roundtrip=claim_parse_test:protocol_names \
	guardian_lease_recovery=capd_test_guardian_test:lease_loss \
	service_descriptor_type_validation=libservice_api_test:api_rejects_invalid_descriptors_and_arguments \
	service_naming_endpoints_confined=libservice_test:naming_exchange_confines_endpoints \
	capsule_bluetooth_wire_validation=req_validate_test:bluetooth_network_requests \
	capsule_strict_wire_validation=req_validate_test:strict_wire_shape \
	capsule_kmod_wire_validation=req_validate_test:kmod_request_validation \
	capsule_service_wire_validation=req_validate_test:service_request_validation \
	procdesc_is_only_signal_authority=switchboard_integration_test:procdesc_is_only_signal_authority \
	capability_tokens_delivered=switchboard_integration_test:capability_tokens_delivered \
	capability_tokens_require_program_activation=switchboard_integration_test:capability_tokens_require_program_activation \
	manifest_arguments_environment=switchboard_integration_test:manifest_arguments_environment \
	remaining_token_families_activate=switchboard_integration_test:remaining_token_families_activate \
	capability_service_descriptors_delivered=switchboard_integration_test:capability_service_descriptors_delivered \
	malformed_reload_is_transactional=switchboard_integration_test:malformed_reload_is_transactional \
	untrusted_bundle_rejected=switchboard_integration_test:untrusted_bundle_rejected \
	kmod_prerequisite_uses_capsule=switchboard_integration_test:kmod_prerequisite_uses_capsule \
	incomplete_capability_set_prevents_exec=switchboard_integration_test:incomplete_capability_set_prevents_exec \
	control_reload_reaches_switchboard=capsule_bootstrap_test:control_reload_reaches_switchboard \
	bootstrap_channel_loss_kills_switchboard=capsule_bootstrap_test:bootstrap_channel_loss_kills_switchboard \
	cap_pro_exec_rotates_nonce=mac_capability_test:cap_pro_exec_rotates_nonce \
	vsock_token_claim_mint_authorize=mac_capability_isolation_test:vsock_token_claim_mint_authorize \
	cap_pro_unshielded_same_session_sigcont_allowed=mac_capability_test:cap_pro_unshielded_same_session_sigcont_allowed \
	cap_pro_pdkill_bypasses_signal_shield=mac_capability_test:cap_pro_pdkill_bypasses_signal_shield \
	cap_pro_pdkill_bypasses_sigkill_shield=mac_capability_test:cap_pro_pdkill_bypasses_sigkill_shield \
	cap_pro_pdkill_bypasses_full_shield=mac_capability_test:cap_pro_pdkill_bypasses_full_shield \
	cap_pro_pdkill_sigterm_through_shield=mac_capability_test:cap_pro_pdkill_sigterm_through_shield \
	cap_pro_foreign_sigcont_blocked=mac_capability_test:cap_pro_foreign_sigcont_blocked \
	ambient_signals_denied_control_shutdown_allowed=capsule_bootstrap_test:ambient_signals_denied_control_shutdown_allowed
total=$#
passed=0
suite_status=0

for case_spec
do
	case_label=${case_spec%%=*}
	case_selector=${case_spec#*=}
	if run_kyua_case "$case_label" "$case_selector"; then
		passed=$((passed + 1))
	else
		suite_status=1
		echo "stopping after first failure to avoid contaminated results" >&2
		break
	fi
done

printf '\nSummary: %d/%d passed\n' "$passed" "$total"
echo "Artifacts retained in $results"
exit "$suite_status"
