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
	atf_check -s exit:64 -e match:usage "$bin" unload
	atf_check -s exit:64 -e match:usage "$bin" load
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

atf_test_case root_status
root_status_head()
{
	atf_set "descr" "A root login session reads status through the read-only view"
}
root_status_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	export TZ=UTC SYSEXT_TEST_ACCESS=root
	cat > expected <<'EOF2'
SystemExtension status (read-only)
built into the kernel: 2 module(s)
  pf zfs
loaded module files:
  if_urndis.ko (id 2)
recent load decisions (oldest first):
  2023-11-14 22:13:20 load accf_http (client devd): refused: client may load hardware drivers only
  2023-11-14 22:13:20 load linux64 (client etc-rc): load failed: Exec format error
EOF2
	atf_check -s exit:0 -o file:expected "$bin" status
	atf_check -s exit:0 -o match:"none since the broker started" \
	    env SYSEXT_TEST=nodecisions "$bin" status
	atf_check -s exit:0 -o inline:"linux64: allowed, boot=disabled, loaded=yes, installed=unknown, policy=default\n  2023-11-14 22:13:20 load linux64 (client etc-rc): load failed: Exec format error\n" "$bin" status linux64
	atf_check -s exit:0 -o match:"no recent load decision" \
	    env SYSEXT_TEST=nodecisions "$bin" status linux64
	atf_check -s exit:0 -o inline:"linux64: loaded, installed=unknown\n" "$bin" list
	atf_check -s exit:0 -o match:"policy=default" "$bin" config
	atf_check -s exit:69 -o ignore -e match:"decisions" env SYSEXT_TEST=io "$bin" status
}
atf_test_case root_mutation_refused
root_mutation_refused_head()
{
	atf_set "descr" "Policy verbs never use the read-only or root-load view"
}
root_mutation_refused_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	export SYSEXT_TEST_ACCESS=root
	# The fake aborts if a load or policy call reaches the read-only view
	# or the root-load endpoint.
	for verb in allow deny reset enable disable; do
		atf_check -s exit:69 -o empty -e match:"cannot reach SystemExtension capability" \
		    "$bin" "$verb" linux64
	done
	for verb in reload restore; do
		atf_check -s exit:69 -o empty -e match:"cannot reach SystemExtension capability" \
		    "$bin" "$verb"
	done
}
atf_test_case nonroot_refused
nonroot_refused_head()
{
	atf_set "descr" "A session without access gets nothing, not even status"
}
nonroot_refused_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	export SYSEXT_TEST_ACCESS=none
	atf_check -s exit:69 -o empty -e match:"cannot reach the SystemExtension status view" \
	    "$bin" status
	atf_check -s exit:69 -o empty -e not-empty "$bin" status linux64
	atf_check -s exit:69 -o empty -e not-empty "$bin" list
	atf_check -s exit:69 -o empty -e not-empty "$bin" config
	atf_check -s exit:69 -o empty -e not-empty "$bin" load linux64
	atf_check -s exit:69 -o empty -e match:"root-load endpoint" \
	    "$bin" unload linux64
}
atf_test_case root_load
root_load_head()
{
	atf_set "descr" "A root login session loads and unloads base modules through the root-load endpoint, with a message for every refusal"
}
root_load_body()
{
	bin="$(atf_get_srcdir)/sysextctl_test_bin"
	export SYSEXT_TEST_ACCESS=root
	atf_check -s exit:0 -o inline:"linux64: loaded\n" "$bin" load linux64
	atf_check -s exit:0 -o inline:"linux64: already loaded\n" \
	    env SYSEXT_TEST=present "$bin" load linux64
	atf_check -s exit:77 -o empty \
	    -e match:"not a file of an installed 5BSD base package" \
	    env SYSEXT_TEST=notpackaged "$bin" load linux64
	atf_check -s exit:77 -o empty -e match:"does not match the checksum" \
	    env SYSEXT_TEST=checksum "$bin" load linux64
	atf_check -s exit:77 -o empty -e match:"no regular module file .*running kernel.s directory" \
	    env SYSEXT_TEST=outside "$bin" load linux64
	atf_check -s exit:77 -o empty -e match:"administrator override" \
	    env SYSEXT_TEST=override "$bin" load linux64
	atf_check -s exit:77 -o empty -e match:"root loads are not configured" \
	    env SYSEXT_TEST=disabled "$bin" load linux64
	atf_check -s exit:77 -o empty -e match:"package database" \
	    env SYSEXT_TEST=pkgdb "$bin" load linux64
	atf_check -s exit:77 -o empty \
	    -e match:"a module file changed, or the kernel loaded a file" \
	    env SYSEXT_TEST=changed "$bin" load linux64
	atf_check -s exit:77 -o empty -e match:"refused: protected module" \
	    env SYSEXT_TEST=protected "$bin" load linux64
	atf_check -s exit:77 -o empty -e match:"refused: protected module" \
	    env SYSEXT_TEST=protected "$bin" unload linux64
	atf_check -s exit:71 -o empty -e match:"load failed: Device busy" \
	    env SYSEXT_TEST=failed "$bin" load linux64
	atf_check -s exit:71 -o empty \
	    -e match:"depends on is loaded from another file, whose version" \
	    env SYSEXT_TEST=version "$bin" load linux64
	atf_check -s exit:71 -o empty \
	    -e match:"unload failed: Device busy \(still loaded: in use" \
	    env SYSEXT_TEST=failed "$bin" unload linux64
	for path in /tmp/linux64.ko /boot/modules/linux64.ko ../linux64; do
		atf_check -s exit:64 -o empty -e match:"paths are refused" \
		    "$bin" load "$path"
	done
	atf_check -s exit:0 -o inline:"linux64: unloaded\n" "$bin" unload linux64
	atf_check -s exit:77 -o empty -e match:"not loaded with sysextctl load" \
	    env SYSEXT_TEST=notroot "$bin" unload linux64
	atf_check -s exit:69 -o empty -e not-empty \
	    env SYSEXT_TEST=io "$bin" load linux64
}
atf_test_case live
live_head()
{
	atf_set "descr" "Installed sysextctl from an ordinary root session: status works, a file outside the base packages is refused, policy verbs are refused, another user is refused"
	atf_set "require.user" "root"
	atf_set "require.progs" "/usr/sbin/sysextctl su"
}
live_body()
{
	if ! pgrep -q -x switchboard; then
		atf_skip "the capability plane is not running"
	fi
	# Run from a process that holds no software grant (kyua from a login
	# shell, cron or rc.local after rc exits); rc's own grant would widen it.
	atf_check -s exit:0 -o match:"^SystemExtension status \(read-only\)" \
	    -o match:"^built into the kernel: [0-9]+ module" \
	    -o match:"^recent load decisions" /usr/sbin/sysextctl status
	atf_check -s exit:0 -o not-empty /usr/sbin/sysextctl config
	# The root-load endpoint answers, and refuses a name with no module
	# file in /boot/kernel (nothing is loaded by this test).
	atf_check -s exit:77 -o empty -e match:"no regular module file" \
	    /usr/sbin/sysextctl load rl_no_such_module
	atf_check -s exit:77 -o empty -e match:"not loaded with sysextctl load" \
	    /usr/sbin/sysextctl unload rl_no_such_module
	atf_check -s exit:1 -o match:"root load rl_no_such_module \(client root \(uid 0\)\): refused" \
	    /usr/sbin/sysextctl status rl_no_such_module
	atf_check -s exit:69 -o empty -e not-empty \
	    /usr/sbin/sysextctl allow if_mos
	atf_check -s exit:69 -o empty -e match:"status view" \
	    env SHELL=/bin/sh su -m nobody -c "/usr/sbin/sysextctl status"
	atf_check -s exit:69 -o empty -e not-empty \
	    env SHELL=/bin/sh su -m nobody -c "/usr/sbin/sysextctl config"
	atf_check -s exit:69 -o empty -e not-empty \
	    env SHELL=/bin/sh su -m nobody -c "/usr/sbin/sysextctl load if_mos"
}

atf_init_test_cases()
{
	atf_add_test_case installed
	atf_add_test_case commands
	atf_add_test_case usage
	atf_add_test_case protocol
	atf_add_test_case root_status
	atf_add_test_case root_mutation_refused
	atf_add_test_case nonroot_refused
	atf_add_test_case root_load
	atf_add_test_case live
}
