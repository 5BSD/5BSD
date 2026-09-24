# SPDX-License-Identifier: BSD-2-Clause
atf_test_case abi_gate
abi_gate_head()
{
	atf_set "descr" "Linux memfd validation and 64-bit syscall parity"
	atf_set "require.arch" "amd64 arm64 aarch64"
	atf_set "require.progs" "clang ld.lld brandelf timeout"
	atf_set "require.user" "root"
	atf_set "timeout" "300"
}
abi_gate_body()
{
	case "$(uname -m)" in
	amd64) target=x86_64-linux-gnu; module=linux64 ;;
	arm64) target=aarch64-linux-gnu; module=linux64 ;;
	*) atf_fail "unsupported architecture" ;;
	esac
	kldstat -q -n "$module.ko" || atf_check -s exit:0 kldload "$module"
	atf_check -s exit:0 -o empty -e empty clang --target="$target" \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o abi_gate \
	    "$(atf_get_srcdir)/linux_abi_gate.c"
	atf_check -s exit:0 -o empty -e empty brandelf -t Linux abi_gate
	atf_check -s exit:0 -o save:cases.txt -e empty ./abi_gate -l
	[ "$(wc -l <cases.txt | tr -d ' ')" -eq 12 ] || atf_fail "missing cases"
	while read -r name; do
		mkdir "$name" || atf_fail "mkdir $name"
		(cd "$name" && timeout 20 ../abi_gate "$name") >stdout.txt 2>stderr.txt
		rc=$?
		cat stdout.txt stderr.txt
		[ "$rc" -eq 0 ] || atf_fail "$name: exit $rc"
	done <cases.txt
}
atf_init_test_cases()
{
	atf_add_test_case abi_gate
}
