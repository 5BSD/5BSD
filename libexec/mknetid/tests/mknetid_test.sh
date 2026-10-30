# SPDX-License-Identifier: BSD-2-Clause

setup()
{
	printf '%s\n' 'alice:*:1001:100:Alice:/home/alice:/bin/sh' \
	    'bob:*:1002:200:Bob:/home/bob:/bin/sh' > passwd
	printf '%s\n' 'primary:*:100:alice' 'extra:*:300:alice,bob' > group
	printf '%s\n' '192.0.2.1 server alias' > hosts
	printf '%s\n' 'unix.extra@example.test 5000:5000' > netid
	printf '%s\n' 'unix.1001@example.test 1001:100,300' \
	    'unix.1002@example.test 1002:200,300' \
	    'unix.server@example.test 0:server' > expected
	program=$(atf_config_get mknetid /usr/libexec/mknetid)
	loader=$(atf_config_get loader '')
}

check_map()
{
	# Installed tests use the system loader; build tests declare their loader.
	if [ -n "$loader" ]; then
		set -- "$loader" "$program" "$@"
	else
		set -- "$program" "$@"
	fi
	atf_check -s exit:0 -o file:expected -e file:errors "$@" \
	    -d example.test -p passwd -g group -h hosts -n netid
}

atf_test_case groups_hosts_extra
groups_hosts_extra_body()
{
	setup
	printf '%s\n' 'unix.extra@example.test 5000:5000' >> expected
	: > errors
	check_map
}

atf_test_case duplicate_warning
duplicate_warning_body()
{
	setup
	printf '%s\n' 'alias:*:1001:100:Alias:/none:/bin/sh' >> passwd
	printf '%s\n' 'unix.extra@example.test 5000:5000' >> expected
	printf '%s\n' "mknetid: duplicate netid 'unix.1001@example.test' -- skipping" > errors
	check_map
}

atf_test_case duplicate_quiet
duplicate_quiet_body()
{
	setup
	printf '%s\n' 'alias:*:1001:100:Alias:/none:/bin/sh' >> passwd
	printf '%s\n' 'unix.extra@example.test 5000:5000' >> expected
	: > errors
	check_map -q
}

atf_test_case optional_netid_missing
optional_netid_missing_body()
{
	setup
	rm netid
	: > errors
	check_map
}

atf_test_case malformed_passwd
malformed_passwd_body()
{
	setup
	printf '%s\n' invalid >> passwd
	printf '%s\n' 'unix.extra@example.test 5000:5000' >> expected
	printf 'mknetid: bad passwd file entry: invalid\n\n' > errors
	check_map
}

atf_test_case required_group_missing
required_group_missing_body()
{
	setup
	rm group
	if [ -n "$loader" ]; then
		set -- "$loader" "$program"
	else
		set -- "$program"
	fi
	atf_check -s exit:1 -o empty \
	    -e inline:'mknetid: group: No such file or directory\n' \
	    "$@" -d example.test -p passwd -g group -h hosts -n netid
}

atf_init_test_cases()
{
	atf_add_test_case groups_hosts_extra
	atf_add_test_case duplicate_warning
	atf_add_test_case duplicate_quiet
	atf_add_test_case optional_netid_missing
	atf_add_test_case malformed_passwd
	atf_add_test_case required_group_missing
}
