# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	# Use the current startup functions with harmless command seams. Never
	# invoke the host's rc configuration, module loader, or device controls.
	# Select rc.subr from the same tree as the scripts, unless explicitly set.
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "${RC_TEST_SRCDIR:-/etc/rc.d}/kld" > kld.sh
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "${RC_TEST_SRCDIR:-/etc/rc.d}/devmatch" > devmatch.sh
	cat > seams.sh <<-'EOF'
	. "${RC_TEST_SUBR:-${RC_TEST_SRCDIR:-/etc/rc.d}/../rc.subr}"
	kenv() {
		case "$2" in
		capability_plane) echo "${PLANE-YES}" ;;
		*) return 1 ;;
		esac
	}
	sysextctl() { echo "broker $*"; return "${BROKER_STATUS:-0}"; }
	kldload() { echo "direct $*"; }
	kldstat() { return "${LOADED_STATUS:-1}"; }
	warn() { echo "$*" >&2; }
	startmsg() { :; }
	info() { :; }
	debug() { :; }
	sysctl() { :; }
	devctl() { echo "devctl $*"; }
	devmatch() { echo if_test.ko; }
	pgrep() { return "${BROKER_RUNNING:-1}"; }
	EOF
}

atf_test_case restore_and_kld_list
restore_and_kld_list_body()
{
	setup
	atf_check -s exit:0 -e empty -o inline:'broker restore\n' \
	    sh -c '. ./seams.sh; . ./kld.sh; kld_start'
	atf_check -s exit:0 -e empty \
	    -o inline:'broker restore\nbroker load first\nbroker load second\n' \
	    sh -c '. ./seams.sh; . ./kld.sh; kld_list="first second"; kld_start'
	atf_check -s exit:1 -e match:'Cannot restore' -o inline:'broker restore\n' \
	    env BROKER_STATUS=1 sh -c \
	    '. ./seams.sh; . ./kld.sh; kld_list=first; kld_start'
	atf_check -s exit:0 -e empty -o inline:'direct first\n' \
	    env PLANE=NO sh -c '. ./seams.sh; . ./kld.sh; kld_list=first; kld_start'
}

atf_test_case loaded_claim_and_denial
loaded_claim_and_denial_body()
{
	setup
	atf_check -s exit:0 -e empty -o inline:'broker load test_module\n' \
	    env LOADED_STATUS=0 sh -c '. ./seams.sh; load_kld -b test_module'
	for loaded in 0 1; do
		atf_check -s exit:1 -e match:'Unable to' \
		    -o inline:'broker load test_module\n' \
		    env LOADED_STATUS="$loaded" BROKER_STATUS=1 sh -c \
		    '. ./seams.sh; load_kld -b test_module'
	done
	atf_check -s exit:0 -e empty -o inline:'direct test_module\n' \
	    sh -c '. ./seams.sh; load_kld test_module'
	# No capability plane, or a jail: -b falls back to the plain path.
	atf_check -s exit:0 -e empty -o inline:'direct test_module\n' \
	    env PLANE=NO sh -c '. ./seams.sh; load_kld -b test_module'
	atf_check -s exit:0 -e empty -o empty \
	    env LOADED_STATUS=0 PLANE=NO sh -c \
	    '. ./seams.sh; load_kld -b test_module'
	atf_check -s exit:0 -e empty -o inline:'direct test_module\n' \
	    sh -c '. ./seams.sh; check_jail() { return 0; };
	    load_kld -b test_module'
}

atf_test_case devmatch_broker
devmatch_broker_body()
{
	setup
	atf_check -s exit:0 -e empty \
	    -o inline:'devctl freeze\nbroker load if_test\ndevctl thaw\n' \
	    env LOADED_STATUS=0 sh -c '. ./seams.sh; . ./devmatch.sh; devmatch_start'
	atf_check -s exit:0 -e match:'Cannot autoload' \
	    -o inline:'devctl freeze\nbroker load if_test\ndevctl thaw\n' \
	    env BROKER_STATUS=1 sh -c '. ./seams.sh; . ./devmatch.sh; devmatch_start'
	# A caller without SystemExtension authority (EX_UNAVAILABLE) is told
	# which processes may load drivers.
	atf_check -s exit:0 -e match:'if_test: only rc at boot' \
	    -o inline:'devctl freeze\nbroker load if_test\ndevctl thaw\n' \
	    env BROKER_STATUS=69 sh -c '. ./seams.sh; . ./devmatch.sh; devmatch_start'
	atf_check -s exit:0 -e empty \
	    -o inline:'devctl freeze\ndirect if_test\ndevctl thaw\n' \
	    env PLANE=NO sh -c '. ./seams.sh; . ./devmatch.sh; devmatch_start'
}

atf_test_case linux_broker
linux_broker_body()
{
	setup
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "${RC_TEST_SRCDIR:-/etc/rc.d}/linux" > linux.sh
	cat > linux-seams.sh <<-'EOF'
	. ./seams.sh
	. ./linux.sh
	sysctl() {
		case "$*" in
		'-n hw.machine_arch') echo amd64 ;;
		'-n compat.linux.emul_path') echo /nonexistent ;;
		'-ni kern.elf64.fallback_brand') echo "${TEST_BRAND:-3}" ;;
		'kern.elf64.fallback_brand=3') return "${FAIL_BRAND:-0}" ;;
		esac
	}
	checkyesno() { [ "${TEST_MOUNTS:-NO}" = YES ]; }
	linux_mount() { echo "mount $*"; [ "$1" != "${FAIL_MOUNT:-}" ]; }
	sysextctl() {
		echo "broker $*"
		[ "$2" != "${FAIL_MODULE:-}" ] && return "${BROKER_STATUS:-0}"
		return 1
	}
	EOF
	for plane in YES "" NO off 0; do
		case "$plane" in
		NO|off|0) loader=direct ;;
		*) loader='broker load' ;;
		esac
		printf '%s\n' "$loader linux64" \
		    "$loader fdescfs" "$loader linprocfs" "$loader linsysfs" > expected
		atf_check -s exit:0 -e empty -o file:expected env PLANE="$plane" \
		    sh -c '. ./linux-seams.sh; linux_start'
	done
	printf '%s\n' 'broker load linux64' 'broker load fdescfs' \
	    'broker load linprocfs' 'broker load linsysfs' > expected
	# A denied ABI write must not be hidden by later successful commands.
	atf_check -s exit:1 -e empty -o file:expected \
	    env TEST_BRAND=-1 FAIL_BRAND=1 TEST_MOUNTS=YES \
	    sh -c '. ./linux-seams.sh; linux_start'
	# Stop at the first failed mount; later success must not mask it.
	printf '%s\n' 'mount linprocfs /nonexistent/proc -o nocover' >> expected
	atf_check -s exit:1 -e empty -o file:expected \
	    env TEST_MOUNTS=YES FAIL_MOUNT=linprocfs \
	    sh -c '. ./linux-seams.sh; linux_start'
	# A broker refusal must not fall back to kldload or attempt mounts.
	atf_check -s exit:1 -e match:'Unable to load' \
	    -o inline:'broker load linux64\n' env BROKER_STATUS=1 TEST_MOUNTS=YES \
	    sh -c '. ./linux-seams.sh; linux_start'
	# A later filesystem-module refusal must also stop before mounting.
	atf_check -s exit:1 -e match:'Unable to load kernel module fdescfs' \
	    -o inline:'broker load linux64\nbroker load fdescfs\n' \
	    env FAIL_MODULE=fdescfs TEST_MOUNTS=YES \
	    sh -c '. ./linux-seams.sh; linux_start'
}

atf_test_case late_load_gate
late_load_gate_head()
{
	atf_set "descr" "load_kld asks the SystemExtension broker only while" \
	    "it runs, and only with the capability plane"
}
late_load_gate_body()
{
	setup
	cat > late-seams.sh <<-'EOF2'
	. ./seams.sh
	kldload() {
		echo "direct $*"
		[ "${DIRECT_STATUS:-0}" = 0 ] || echo "kldload: refused" >&2
		return "${DIRECT_STATUS:-0}"
	}
	sysextctl() {
		echo "broker $*"
		[ "${BROKER_STATUS:-0}" = 0 ] || echo "sysextctl: denied" >&2
		return "${BROKER_STATUS:-0}"
	}
	EOF2
	# Before rc.d/kld starts the broker the direct load is the only path:
	# a failure is reported with kldload's own message and sysextctl,
	# which would start the broker early, is not run.
	atf_check -s exit:0 -o inline:'direct mac_ntpd\n' -e empty \
	    sh -c '. ./late-seams.sh; load_kld mac_ntpd'
	atf_check -s exit:1 -o inline:'direct mac_ntpd\n' \
	    -e match:'kldload: refused' \
	    -e match:'Unable to load kernel module mac_ntpd' \
	    -e not-match:broker env DIRECT_STATUS=1 \
	    sh -c '. ./late-seams.sh; load_kld mac_ntpd'
	# While the broker runs the load goes through it, never kldload(2);
	# its errors are not hidden, and a refusal is final.
	atf_check -s exit:0 -o empty -e empty env BROKER_RUNNING=0 \
	    sh -c '. ./late-seams.sh; load_kld mac_ntpd'
	atf_check -s exit:1 -o empty -e match:'sysextctl: denied' \
	    -e match:'Unable to load kernel module mac_ntpd' \
	    env BROKER_RUNNING=0 BROKER_STATUS=1 \
	    sh -c '. ./late-seams.sh; load_kld mac_ntpd'
	# required_modules uses the same path.
	atf_check -s exit:0 -o inline:'direct geom_uzip\n' -e empty \
	    sh -c '. ./late-seams.sh; required_modules=geom_uzip;
	    check_required_after start'
	atf_check -s exit:0 -o empty -e empty env BROKER_RUNNING=0 \
	    sh -c '. ./late-seams.sh; required_modules=geom_uzip;
	    check_required_after start'
	# Without the plane, or in a jail, there is no broker to ask.
	for plane in NO off 0; do
		atf_check -s exit:0 -o inline:'direct mac_ntpd\n' -e empty \
		    env PLANE="$plane" BROKER_RUNNING=0 \
		    sh -c '. ./late-seams.sh; load_kld mac_ntpd'
	done
	atf_check -s exit:0 -o inline:'direct mac_ntpd\n' -e empty \
	    env BROKER_RUNNING=0 sh -c '. ./late-seams.sh;
	    check_jail() { return 0; }; load_kld mac_ntpd'
}

atf_test_case late_load_broker_process cleanup
late_load_broker_process_head()
{
	atf_set "descr" "load_kld takes only user capability's BSDExtension for the broker"
}
late_load_broker_process_body()
{
	local expect

	setup
	# A process named BSDExtension run by the test's user, seen by the
	# real pgrep(1), is not the broker; the host's own broker, run as
	# user capability, is.
	[ "$(id -un)" = capability ] && atf_skip "runs as the broker's user"
	cp /bin/sleep BSDExtension
	./BSDExtension 60 >/dev/null 2>&1 &
	echo $! > broker.pid
	if pgrep -q -x -U capability BSDExtension; then
		expect='broker load mac_ntpd\n'
	else
		expect='direct mac_ntpd\n'
	fi
	atf_check -s exit:0 -o empty -e inline:"${expect}" \
	    sh -c '. ./seams.sh; unset -f pgrep;
	    sysextctl() { echo "broker $*" >&2; };
	    kldload() { echo "direct $*" >&2; }; load_kld mac_ntpd'
}
late_load_broker_process_cleanup()
{
	[ -f broker.pid ] && kill "$(cat broker.pid)" 2>/dev/null
	return 0
}

atf_init_test_cases()
{
	atf_add_test_case restore_and_kld_list
	atf_add_test_case loaded_claim_and_denial
	atf_add_test_case linux_broker
	atf_add_test_case devmatch_broker
	atf_add_test_case late_load_gate
	atf_add_test_case late_load_broker_process
}
