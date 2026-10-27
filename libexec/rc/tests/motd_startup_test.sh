# SPDX-License-Identifier: BSD-2-Clause

atf_test_case prepared_configuration
prepared_configuration_body()
{
	# Exercise the actual function after generation construction has supplied
	# the template and alias. These seams model command admission, not BIP.
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "${RC_TEST_SRCDIR:-/etc/rc.d}/motd" > startup.sh
	mkdir etc run tmp
	echo 'Owner supplied notice' > etc/motd.template
	ln -s ../run/motd etc/motd
	cp etc/motd.template expected-template
	cat > exercise.sh <<-'SEAMS'
	. ./startup.sh
	COMPAT_MOTD="$PWD/etc/motd"
	TEMPLATE="$PWD/etc/motd.template"
	TARGET="$PWD/run/motd"
	TMPDIR="$PWD/tmp"
	export TMPDIR
	startmsg() { :; }
	uname() { echo 'FreeBSD 16.0 test kernel'; }
	ln() { echo ln >> forbidden; return 1; }
	chmod() { echo chmod >> forbidden; return 1; }
	install() {
		previous= last=
		for argument; do previous=$last; last=$argument; done
		if [ "$last" != "$TARGET" ]; then
			echo "install $last" >> forbidden
			return 1
		fi
		cp "$previous" "$last"
	}
	rm() {
		for argument; do
			case "$argument" in
			"$COMPAT_MOTD"|"$TEMPLATE") echo rm >> forbidden; return 1 ;;
			esac
		done
		command rm "$@"
	}
	motd_start
	SEAMS
	atf_check -s exit:0 -o empty -e empty sh exercise.sh
	atf_check -s exit:0 -o inline:'5BSD 16.0 (kernel) test\nOwner supplied notice\n' cat run/motd
	atf_check -s exit:0 -o empty cmp expected-template etc/motd.template
	atf_check -s exit:0 -o inline:'../run/motd\n' readlink etc/motd
	atf_check -s exit:0 -o empty test ! -e forbidden
	atf_check -s exit:0 -o empty find tmp -type f
}

migration_setup()
{
	sed '/^\. \/etc\/rc.subr$/d; /^load_rc_config /d; /^run_rc_command /d' \
	    "${RC_TEST_SRCDIR:-/etc/rc.d}/motd" > startup.sh
	mkdir etc run tmp
	printf 'FreeBSD old kernel\nKeep this notice\n' > etc/motd
	cp etc/motd original
	cat > migrate.sh <<-'SEAMS'
	. ./startup.sh
	COMPAT_MOTD="$PWD/etc/motd"
	TEMPLATE="$PWD/etc/motd.template"
	TARGET="$PWD/run/motd"
	TMPDIR="${TEST_TMPDIR:-$PWD/tmp}"
	export TMPDIR
	startmsg() { :; }
	warn() { echo "$*" >&2; }
	uname() { [ "${FAIL_STAGE:-}" != uname ] || return 1; echo 'FreeBSD 16.0 test kernel'; }
	mktemp() { [ "${FAIL_STAGE:-}" != mktemp ] || return 1; command mktemp "$@"; }
	cat() { [ "${FAIL_STAGE:-}" != cat ] || return 1; command cat "$@"; }
	sed() { [ "${FAIL_STAGE:-}" != sed ] || return 1; command sed "$@"; }
	chmod() { [ "${FAIL_STAGE:-}" != chmod ] || return 1; command chmod "$@"; }
	mv() { [ "${FAIL_STAGE:-}" != mv ] || return 1; command mv "$@"; }
	ln() { [ "${FAIL_STAGE:-}" != ln ] || return 1; command ln "$@"; }
	install() {
		[ "${FAIL_STAGE:-}" != install ] || return 1
		previous= last=
		for argument; do previous=$last; last=$argument; done
		[ "$last" = "$TARGET" ] || return 1
		cp "$previous" "$last"
	}
	motd_start
	SEAMS
}

atf_test_case migration_failure_preserves_message
migration_failure_preserves_message_body()
{
	migration_setup
	for stage in sed chmod mv; do
		atf_check -s exit:1 -o empty -e match:'Unable to' \
		    env FAIL_STAGE="$stage" sh migrate.sh
		atf_check -s exit:0 -o empty cmp original etc/motd
		atf_check -s exit:0 -o empty test ! -L etc/motd
		atf_check -s exit:0 -o empty test ! -e etc/motd.template
		atf_check -s exit:0 -o empty find etc -name 'motd.template.*'
	done
}

atf_test_case successful_migration
successful_migration_body()
{
	migration_setup
	atf_check -s exit:0 -o empty -e empty sh migrate.sh
	atf_check -s exit:0 -o inline:'Keep this notice\n' cat etc/motd.template
	atf_check -s exit:0 -o inline:'5BSD 16.0 (kernel) test\nKeep this notice\n' cat run/motd
	atf_check -s exit:0 -o empty test -L etc/motd
	atf_check -s exit:0 -o empty find etc -name 'motd.template.*'
	atf_check -s exit:0 -o empty find tmp -type f
}

runtime_setup()
{
	migration_setup
	printf 'Keep this notice\n' > etc/motd.template
	rm etc/motd
	ln -s ../run/motd etc/motd
	echo previous > run/motd
}

atf_test_case runtime_failures
runtime_failures_body()
{
	runtime_setup
	for stage in uname mktemp sed cat install; do
		atf_check -s exit:1 -o empty -e match:'Unable to' \
		    env FAIL_STAGE="$stage" sh migrate.sh
		atf_check -s exit:0 -o inline:'previous\n' cat run/motd
		atf_check -s exit:0 -o inline:'Keep this notice\n' cat etc/motd.template
		atf_check -s exit:0 -o empty find tmp -type f
	done
}

atf_test_case temporary_directory_with_spaces
temporary_directory_with_spaces_body()
{
	runtime_setup
	mkdir 'temporary files'
	atf_check -s exit:0 -o empty -e empty \
	    env TEST_TMPDIR="$PWD/temporary files" sh migrate.sh
	atf_check -s exit:0 -o inline:'5BSD 16.0 (kernel) test\nKeep this notice\n' cat run/motd
	atf_check -s exit:0 -o empty find 'temporary files' -type f
}

atf_test_case configuration_failures
configuration_failures_body()
{
	runtime_setup
	rm etc/motd
	atf_check -s exit:1 -o empty -e match:'Unable to' \
	    env FAIL_STAGE=ln sh migrate.sh
	atf_check -s exit:0 -o inline:'previous\n' cat run/motd
	atf_check -s exit:0 -o empty test ! -L etc/motd
	rm etc/motd.template
	atf_check -s exit:1 -o empty -e match:'Unable to' \
	    env FAIL_STAGE=install sh migrate.sh
	atf_check -s exit:0 -o empty test ! -e etc/motd.template
	atf_check -s exit:0 -o empty test ! -L etc/motd
	atf_check -s exit:0 -o inline:'previous\n' cat run/motd
}

atf_init_test_cases()
{
	atf_add_test_case prepared_configuration
	atf_add_test_case migration_failure_preserves_message
	atf_add_test_case successful_migration
	atf_add_test_case configuration_failures
	atf_add_test_case runtime_failures
	atf_add_test_case temporary_directory_with_spaces
}
