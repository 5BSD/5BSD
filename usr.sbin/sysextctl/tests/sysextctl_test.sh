# SPDX-License-Identifier: BSD-2-Clause
atf_test_case commands
commands_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	atf_check -s exit:0 -o inline:"linux64: loaded, installed=unknown\n" "$bin" list
	atf_check -s exit:0 -o inline:"linux64: allowed, installed=unknown\n" env SYSEXT_TEST=absent "$bin" list
	atf_check -s exit:0 -o empty env SYSEXT_TEST=hidden "$bin" list
	atf_check -s exit:0 -o match:"loaded=undisclosed" env SYSEXT_TEST=hidden "$bin" config
	atf_check -s exit:0 -o match:"policy=default" "$bin" config
	for verb in allow deny reset enable disable; do
		atf_check -s exit:0 -o match:"$verb saved" "$bin" "$verb" linux64
		atf_check -s exit:69 -e not-empty env SYSEXT_TEST=denied "$bin" "$verb" linux64
	done
	atf_check -s exit:0 -o match:"activations restored" "$bin" restore
	atf_check -s exit:0 -o inline:"linux64: allowed, boot=disabled, loaded=yes, installed=unknown, policy=default\n" "$bin" status linux64
	atf_check -s exit:0 -o inline:"linux64: loaded\n" "$bin" load linux64
	atf_check -s exit:0 -o inline:"SystemExtension defaults reloaded; administrator overrides preserved\n" "$bin" reload
	atf_check -s exit:1 -o inline:"linux64: allowed, boot=disabled, loaded=no, installed=unknown, policy=default\n" env SYSEXT_TEST=absent "$bin" status linux64
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
atf_test_case installed
installed_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	mkdir modules other
	export SYSEXT_TEST_MODULE_PATH="$(pwd)/other;$(pwd)/modules"
	atf_check -s exit:0 -o inline:"linux64: loaded, installed=no\n" "$bin" list
	touch modules/linux64.ko
	atf_check -s exit:0 -o inline:"linux64: allowed, installed=yes\n" env SYSEXT_TEST=absent "$bin" list
	atf_check -s exit:1 -o match:"loaded=no, installed=yes" env SYSEXT_TEST=absent "$bin" status linux64
	mv modules/linux64.ko modules/linux64
	atf_check -s exit:0 -o match:"installed=yes" "$bin" list
	rm modules/linux64
	mkdir modules/linux64.ko
	atf_check -s exit:0 -o match:"installed=no" "$bin" list
	atf_check -s exit:0 -o match:"installed=unknown" env SYSEXT_TEST_MODULE_PATH=relative "$bin" list
	atf_check -s exit:0 -o match:"loaded=undisclosed, installed=no" env SYSEXT_TEST=hidden "$bin" config
}

atf_init_test_cases()
{
	atf_add_test_case installed
	atf_add_test_case commands
	atf_add_test_case usage
	atf_add_test_case protocol
}
