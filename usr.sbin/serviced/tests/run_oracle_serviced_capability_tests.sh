#!/bin/sh
#
# Run the focused Oracle/serviced capability suite under Kyua.  Kyua owns
# test isolation, timeout enforcement, cleanup phases, and result reporting.
#

set -u

usage()
{
	cat <<EOF
usage: $(basename "$0") [-o objtop] [-r results-directory]

Run as root.  objtop defaults to the native /usr/obj path for this source
tree.  The Kyua database, log, staged suite, and report are retained.
EOF
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
srcroot=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
machine=$(uname -m)
machine_arch=$(uname -p)
objtop="/usr/obj${srcroot}/${machine}.${machine_arch}"
results=

while getopts "o:r:h" opt; do
	case "$opt" in
	o)	objtop=$OPTARG ;;
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
			if (name == "oracled" || name == "serviced") {
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
if [ ! -r /dev/mac_capability ] || [ ! -w /dev/mac_capability ]; then
	echo "error: /dev/mac_capability is unavailable" >&2
	exit 77
fi
if ! command -v kyua >/dev/null 2>&1; then
	echo "error: kyua is required" >&2
	exit 69
fi

if [ -z "$results" ]; then
	results=$(mktemp -d /tmp/oracle-serviced-root.XXXXXX) || exit 1
else
	mkdir -p "$results" || exit 1
	results=$(CDPATH= cd -- "$results" && pwd)
fi

oracled_dir="$objtop/usr.sbin/oracled"
oraclectl_dir="$objtop/usr.sbin/oraclectl"
serviced_dir="$objtop/usr.sbin/serviced"
serviced_test_dir="$objtop/usr.sbin/serviced/tests"
oracled_test_dir="$objtop/usr.sbin/oracled/tests"
oraclert_dir="$objtop/lib/liboraclert"
service_lib_dir="$objtop/lib/libservice"
mac_test_dir="$objtop/tests/sys/mac_capability"

for executable in \
	"$oracled_dir/oracled" \
	"$oraclectl_dir/oraclectl" \
	"$serviced_dir/serviced" \
	"$serviced_test_dir/serviced_integration_test" \
	"$oracled_test_dir/oracled_bootstrap_test" \
	"$mac_test_dir/mac_capability_test" \
	"$mac_test_dir/mac_capability_shield_helper"
do
	if [ ! -x "$executable" ]; then
		echo "error: required development binary not found: $executable" >&2
		echo "hint: build it or override the object root with -o objtop" >&2
		exit 66
	fi
done

PATH="$oracled_dir:$oraclectl_dir:$serviced_dir:$oraclert_dir:/usr/bin:/bin:/usr/sbin:/sbin"
LD_LIBRARY_PATH="$service_lib_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH LD_LIBRARY_PATH

suite_dir="$results/suite"
mkdir -p "$suite_dir" || exit 1
install -m 0444 "$script_dir/CapabilityKyuafile" "$suite_dir/Kyuafile" || exit 1
install -m 0444 "$script_dir/test_helpers.sh" "$suite_dir/test_helpers.sh" || exit 1
# Do not copy executable test programs into /tmp: that filesystem is
# commonly MNT_NOSUID, and FreeBSD intentionally suppresses MAC exec
# credential transitions there.  Symlinks keep the executed vnode on the
# development object filesystem, so fork+exec rotates the program nonce.
ln -s "$serviced_test_dir/serviced_integration_test" \
	"$suite_dir/serviced_integration_test" || exit 1
ln -s "$oracled_test_dir/oracled_bootstrap_test" \
	"$suite_dir/oracled_bootstrap_test" || exit 1
ln -s "$mac_test_dir/mac_capability_test" \
	"$suite_dir/mac_capability_test" || exit 1
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
	if kyua -c none --logfile="$results/$case_label.kyua.log" test \
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

total=10
passed=0
suite_status=0

for case_spec in \
	procdesc_is_only_signal_authority=serviced_integration_test:procdesc_is_only_signal_authority \
	capability_tokens_delivered=serviced_integration_test:capability_tokens_delivered \
	capability_tokens_require_program_activation=serviced_integration_test:capability_tokens_require_program_activation \
	incomplete_capability_set_prevents_exec=serviced_integration_test:incomplete_capability_set_prevents_exec \
	bootstrap_channel_loss_kills_serviced=oracled_bootstrap_test:bootstrap_channel_loss_kills_serviced \
	cap_pro_exec_rotates_nonce=mac_capability_test:cap_pro_exec_rotates_nonce \
	cap_pro_pdkill_bypasses_signal_shield=mac_capability_test:cap_pro_pdkill_bypasses_signal_shield \
	cap_pro_pdkill_bypasses_sigkill_shield=mac_capability_test:cap_pro_pdkill_bypasses_sigkill_shield \
	cap_pro_pdkill_bypasses_full_shield=mac_capability_test:cap_pro_pdkill_bypasses_full_shield \
	cap_pro_pdkill_sigterm_through_shield=mac_capability_test:cap_pro_pdkill_sigterm_through_shield
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
