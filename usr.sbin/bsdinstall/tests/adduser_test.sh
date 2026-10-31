#!/usr/bin/env atf-sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# The installer's adduser step offers the local hardware groups (audio,
# video) as the default additional groups, and BSDINSTALL_ADDUSER_GROUPS
# overrides or empties that default.  chroot(8) is replaced by a recorder.

adduser_script()
{
	printf '%s' "${BSDINSTALL_ADDUSER_SCRIPT:-/usr/libexec/bsdinstall/adduser}"
}

make_stubs()
{
	mkdir -p bin
	cat > bin/chroot <<'EOS'
#!/bin/sh
for a; do printf '[%s]' "$a"; done > "$CHROOT_LOG"
echo >> "$CHROOT_LOG"
EOS
	printf '#!/bin/sh\n:\n' > bin/clear
	chmod +x bin/chroot bin/clear
}

atf_test_case default_groups
default_groups_head()
{
	atf_set "descr" "adduser is offered audio and video by default"
}
default_groups_body()
{
	make_stubs
	atf_check -o ignore env -u BSDINSTALL_ADDUSER_GROUPS \
	    PATH="$PWD/bin:$PATH" CHROOT_LOG="$PWD/log" \
	    BSDINSTALL_CHROOT=/mnt sh "$(adduser_script)"
	atf_check -o inline:"[/mnt][adduser][-G][audio video]\n" cat log
}

atf_test_case override_groups
override_groups_head()
{
	atf_set "descr" "BSDINSTALL_ADDUSER_GROUPS replaces or empties the default"
}
override_groups_body()
{
	make_stubs
	atf_check -o ignore env PATH="$PWD/bin:$PATH" CHROOT_LOG="$PWD/log" \
	    BSDINSTALL_CHROOT=/mnt BSDINSTALL_ADDUSER_GROUPS="wheel audio" \
	    sh "$(adduser_script)"
	atf_check -o inline:"[/mnt][adduser][-G][wheel audio]\n" cat log
	atf_check -o ignore env PATH="$PWD/bin:$PATH" CHROOT_LOG="$PWD/log" \
	    BSDINSTALL_CHROOT=/mnt BSDINSTALL_ADDUSER_GROUPS= \
	    sh "$(adduser_script)"
	atf_check -o inline:"[/mnt][adduser][-G][]\n" cat log
}

atf_test_case groups_are_base_groups
groups_are_base_groups_head()
{
	atf_set "descr" "The default groups exist on a new system"
}
groups_are_base_groups_body()
{
	for g in audio video; do
		atf_check -o match:"^$g:" grep "^$g:" /usr/share/base-accounts/group
	done
}

atf_init_test_cases()
{
	atf_add_test_case default_groups
	atf_add_test_case override_groups
	atf_add_test_case groups_are_base_groups
}
