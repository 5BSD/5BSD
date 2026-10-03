# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	# Use the current startup functions with harmless command seams. Never
	# invoke the host's rc configuration, module loader, or device controls.
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    @SRCTOP@/libexec/rc/rc.d/kld > kld.sh
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    @SRCTOP@/libexec/rc/rc.d/devmatch > devmatch.sh
	cat > seams.sh <<-'EOF'
	. @SRCTOP@/libexec/rc/rc.subr
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
	atf_check -s exit:0 -e empty \
	    -o inline:'devctl freeze\ndirect -n if_test\ndevctl thaw\n' \
	    env PLANE=NO sh -c '. ./seams.sh; . ./devmatch.sh; devmatch_start'
}

atf_test_case linux_broker
linux_broker_body()
{
	setup
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    @SRCTOP@/libexec/rc/rc.d/linux > linux.sh
	cat > linux-seams.sh <<-'EOF'
	. ./seams.sh
	. ./linux.sh
	sysctl() {
		case "$*" in
		'-n hw.machine_arch') echo amd64 ;;
		'-n compat.linux.emul_path') echo /nonexistent ;;
		'-ni kern.elf64.fallback_brand') echo 3 ;;
		esac
	}
	checkyesno() { [ "${TEST_MOUNTS:-NO}" = YES ]; }
	linux_mount() { echo "mount $*"; }
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
		printf '%s\n' "$loader linux64" "$loader pty" \
		    "$loader fdescfs" "$loader linprocfs" "$loader linsysfs" > expected
		atf_check -s exit:0 -e empty -o file:expected env PLANE="$plane" \
		    sh -c '. ./linux-seams.sh; linux_start'
	done
	# A broker refusal must not fall back to kldload or attempt mounts.
	atf_check -s exit:1 -e match:'Unable to load' \
	    -o inline:'broker load linux64\n' env BROKER_STATUS=1 TEST_MOUNTS=YES \
	    sh -c '. ./linux-seams.sh; linux_start'
	# A later filesystem-module refusal must also stop before mounting.
	atf_check -s exit:1 -e match:'Unable to load kernel module fdescfs' \
	    -o inline:'broker load linux64\nbroker load pty\nbroker load fdescfs\n' \
	    env FAIL_MODULE=fdescfs TEST_MOUNTS=YES \
	    sh -c '. ./linux-seams.sh; linux_start'
}

atf_init_test_cases()
{
	atf_add_test_case restore_and_kld_list
	atf_add_test_case loaded_claim_and_denial
	atf_add_test_case linux_broker
	atf_add_test_case devmatch_broker
}
