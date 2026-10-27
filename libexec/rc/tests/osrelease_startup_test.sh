# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "${RC_TEST_SRCDIR:-/etc/rc.d}/os-release" > startup.sh
	cat > seams.sh <<-'SEAMS'
	. ./startup.sh
	osrelease_file="$PWD/output"
	startmsg() { [ "$*" != 'done.' ] || echo done; }
	warn() { echo "$*" >&2; }
	freebsd-version() {
		[ "${FAIL_VERSION:-0}" = 0 ] || return 1
		echo 16.0-test
	}
	mktemp() {
		[ "${FAIL_TEMP:-0}" = 0 ] || return 1
		command mktemp "$PWD/metadata.XXXXXX"
	}
	install() {
		echo attempted >> install.log
		[ "${FAIL_INSTALL:-0}" = 0 ] || return 1
		previous= last=
		for argument; do previous=$last; last=$argument; done
		cp "$previous" "$last"
	}
	SEAMS
}

atf_test_case installed_metadata
installed_metadata_body()
{
	setup
	atf_check -s exit:0 -o inline:'done\n' -e empty \
	    sh -c '. ./seams.sh; osrelease_start'
	atf_check -s exit:0 -o match:'VERSION="16.0-test"' cat output
	atf_check -s exit:0 -o empty sh -c \
	    'for path in metadata.*; do [ ! -e "$path" ] || exit 1; done'
}

atf_test_case denied_install
denied_install_body()
{
	setup
	echo previous > output
	atf_check -s exit:1 -o empty -e match:'Unable to update' \
	    env FAIL_INSTALL=1 sh -c '. ./seams.sh; osrelease_start'
	atf_check -s exit:0 -o inline:'previous\n' cat output
	atf_check -s exit:0 -o inline:'attempted\n' cat install.log
	atf_check -s exit:0 -o empty sh -c \
	    'for path in metadata.*; do [ ! -e "$path" ] || exit 1; done'
}

atf_test_case failed_inputs
failed_inputs_body()
{
	setup
	for failure in FAIL_VERSION FAIL_TEMP; do
		atf_check -s exit:1 -o empty -e match:'Unable to' \
		    env "$failure=1" sh -c '. ./seams.sh; osrelease_start'
		atf_check -s exit:0 -o empty test ! -e install.log
		atf_check -s exit:0 -o empty test ! -e output
	done
}

atf_init_test_cases()
{
	atf_add_test_case installed_metadata
	atf_add_test_case denied_install
	atf_add_test_case failed_inputs
}
