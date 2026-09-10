#!/usr/bin/env atf-sh

atf_test_case multiconsole_preserves_lifecycle_channel
multiconsole_preserves_lifecycle_channel_body()
{
	child="@SRCTOP@/usr.sbin/bsdinstall/runconsoles/child.c"

	# The live installer runs below runconsoles, whose descriptor scrub must
	# retain the ambient channel used by shutdown(8) and reboot(8).
	atf_check -s exit:0 -o ignore grep -F \
	    'value = getenv("SERVICE_LOOKUP_FD");' "$child"
	atf_check -s exit:0 -o ignore grep -F \
	    'closefrom_except_ambient();' "$child"
}

atf_init_test_cases()
{
	atf_add_test_case multiconsole_preserves_lifecycle_channel
}
