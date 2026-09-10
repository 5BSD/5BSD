#!/usr/bin/env atf-sh

hostname_helper()
{
	if [ -n "${BSDINSTALL_HOSTNAME_HELPER:-}" ]; then
		printf '%s' "$BSDINSTALL_HOSTNAME_HELPER"
	else
		printf '%s' @SRCTOP@/usr.sbin/bsdinstall/scripts/hostname.subr
	fi
}

atf_test_case valid_names
valid_names_body()
{
	. "$(hostname_helper)"

	for name in 5BSD fivebsd-vm host.example test-01.example.org; do
		bsdinstall_valid_hostname "$name" ||
		    atf_fail "valid hostname rejected: $name"
	done
}

atf_test_case invalid_names
invalid_names_body()
{
	. "$(hostname_helper)"
	tab=$(printf '\t')
	control=$(printf '\025')
	long_label=$(jot -b a -s '' 64)

	for name in '' . example. .example two..dots -leading trailing- \
	    "bad${tab}name" "bad${control}name" 'bad$name' 'bad"name' \
	    "$long_label.example"; do
		if bsdinstall_valid_hostname "$name"; then
			atf_fail "invalid hostname accepted: $name"
		fi
	done
}

atf_init_test_cases()
{
	atf_add_test_case valid_names
	atf_add_test_case invalid_names
}
