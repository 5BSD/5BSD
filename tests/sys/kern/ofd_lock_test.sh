# SPDX-License-Identifier: BSD-2-Clause
atf_test_case native cleanup
native_head()
{
	atf_set descr "Native OFD lock ranges, ownership, conflicts and interrupted waits"
	atf_set require.progs "cc timeout mount umount"
	atf_set require.user root
	atf_set timeout 300
}
atf_test_case linux cleanup
linux_head()
{
	atf_set descr "Linux OFD lock ranges, ownership, conflicts and interrupted waits"
	atf_set require.arch "amd64 arm64 aarch64"
	atf_set require.progs "clang ld.lld brandelf timeout mount umount"
	atf_set require.user root
	atf_set timeout 300
}
run_cases()
{
	atf_check -s exit:0 mkdir fs
	atf_check -s exit:0 mount -t tmpfs tmpfs fs
	atf_check -s exit:0 cp ofd fs/ofd
	if [ -f ofd_extra ]; then atf_check -s exit:0 cp ofd_extra fs/ofd_extra; fi
	cd fs || atf_fail "cd fs"
	atf_check -s exit:0 -o save:cases.txt ./ofd -l
	[ "$(wc -l <cases.txt | tr -d ' ')" -eq 15 ] || atf_fail "missing cases"
	while read -r name; do
		mkdir "$name" || atf_fail "mkdir $name"
		(cd "$name" && timeout 20 ../ofd "$name") >stdout.txt 2>stderr.txt
		rc=$?
		cat stdout.txt stderr.txt
		[ "$rc" -eq 0 ] || atf_fail "$name: exit $rc"
	done <cases.txt
	if [ -f ofd_extra ]; then atf_check -s exit:0 timeout 20 ./ofd_extra; fi
	cd .. || atf_fail "cd .."
	atf_check -s exit:0 umount fs
}
native_body()
{
	atf_check -s exit:0 cc -O2 -Wall -Wextra -Werror -pthread -o ofd_extra "$(atf_get_srcdir)/ofd_native_extra.c"
	atf_check -s exit:0 cc -O2 -Wall -Wextra -Werror -o ofd "$(atf_get_srcdir)/ofd_lock.c"
	run_cases
}
linux_body()
{
	case "$(uname -m)" in
	amd64) target=x86_64-linux-gnu ;;
	arm64) target=aarch64-linux-gnu ;;
	*) atf_fail "unsupported architecture" ;;
	esac
	kldstat -q -n linux64.ko || atf_check -s exit:0 kldload linux64
	atf_check -s exit:0 clang --target="$target" -DLINUX_ABI -fuse-ld=lld \
	    -nostdlib -static -fno-stack-protector -fno-builtin -O2 -Wall -Wextra \
	    -Werror -o ofd "$(atf_get_srcdir)/ofd_lock.c"
	atf_check -s exit:0 brandelf -t Linux ofd
	run_cases
}
native_cleanup() { umount fs 2>/dev/null || true; }
linux_cleanup() { umount fs 2>/dev/null || true; }
atf_init_test_cases()
{
	atf_add_test_case native
	atf_add_test_case linux
}
