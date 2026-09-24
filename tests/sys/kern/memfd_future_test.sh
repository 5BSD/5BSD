# SPDX-License-Identifier: BSD-2-Clause
atf_test_case native
native_head()
{
	atf_set descr "Native FUTURE_WRITE seal enforcement and mapping lifetime"
	atf_set require.progs "cc timeout"
	atf_set timeout 180
}
atf_test_case linux
linux_head()
{
	atf_set descr "Linux FUTURE_WRITE seal enforcement and mapping lifetime"
	atf_set require.arch "amd64 arm64 aarch64"
	atf_set require.progs "clang ld.lld brandelf timeout"
	atf_set require.user root
	atf_set timeout 180
}
run_cases()
{
	atf_check -s exit:0 -o save:cases.txt ./seal -l
	[ "$(wc -l <cases.txt | tr -d ' ')" -eq "$1" ] || atf_fail "missing cases"
	while read -r name; do
		mkdir "$name" || atf_fail "mkdir $name"
		(cd "$name" && timeout 20 ../seal "$name") >stdout.txt 2>stderr.txt
		rc=$?
		cat stdout.txt stderr.txt
		[ "$rc" -eq 0 ] || atf_fail "$name: exit $rc"
	done <cases.txt
}
native_body()
{
	atf_check -s exit:0 cc -O2 -Wall -Wextra -Werror -o seal "$(atf_get_srcdir)/memfd_future.c"
	run_cases 7
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
	    -Werror -o seal "$(atf_get_srcdir)/memfd_future.c"
	atf_check -s exit:0 brandelf -t Linux seal
	run_cases 6
}
atf_init_test_cases()
{
	atf_add_test_case native
	atf_add_test_case linux
}
