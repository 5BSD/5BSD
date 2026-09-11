# SPDX-License-Identifier: BSD-2-Clause
atf_test_case commands
commands_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	atf_check -s exit:0 -o inline:"linux64\n" "$bin" list
	atf_check -s exit:0 -o inline:"linux64: loaded\n" "$bin" status linux64
	atf_check -s exit:0 -o inline:"linux64: loaded\n" "$bin" load linux64
	atf_check -s exit:0 -o inline:"SystemExtension policy reloaded\n" "$bin" reload
	atf_check -s exit:1 -o inline:"linux64: not loaded\n" env SYSEXT_TEST=absent "$bin" status linux64
}
atf_test_case usage
usage_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	atf_check -s exit:64 -e match:usage "$bin" unload linux64
	for name in /tmp/linux64.ko ../linux64 . .. ""; do
		atf_check -s exit:64 -e match:"invalid module" "$bin" load "$name"
	done
}
atf_test_case protocol
protocol_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	for mode in short count name errno; do
		atf_check -s exit:76 -e not-empty env SYSEXT_TEST="$mode" "$bin" list
	done
	atf_check -s exit:76 -e not-empty env SYSEXT_TEST=state "$bin" status linux64
	atf_check -s exit:76 -e not-empty env SYSEXT_TEST=state "$bin" load linux64
	atf_check -s exit:69 -e not-empty env SYSEXT_TEST=denied "$bin" load linux64
	atf_check -s exit:69 -e not-empty env SYSEXT_TEST=denied "$bin" reload
	atf_check -s exit:69 -e not-empty env SYSEXT_TEST=io "$bin" list
}
atf_init_test_cases()
{
	atf_add_test_case commands
	atf_add_test_case usage
	atf_add_test_case protocol
}
