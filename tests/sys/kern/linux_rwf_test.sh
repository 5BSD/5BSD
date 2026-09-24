# SPDX-License-Identifier: BSD-2-Clause
atf_test_case rwf
rwf_head()
{
	atf_set "descr" "Linux preadv2/pwritev2 RWF_* flags"
	atf_set "require.arch" "amd64 arm64 aarch64"
	atf_set "require.progs" "clang ld.lld brandelf df awk"
	atf_set "require.kmods" "linux64"
	atf_set "require.user" "root"
	atf_set "timeout" "60"
}
rwf_body()
{
	df -T / | awk 'NR == 2 && $2 == "zfs" {ok=1} END {exit !ok}' ||
	    atf_fail "requires the disposable ZFS-root VM"
	case "$(uname -m)" in
	amd64) target=x86_64-linux-gnu ;;
	arm64) target=aarch64-linux-gnu ;;
	*) atf_fail "unsupported architecture" ;;
	esac
	atf_check -s exit:0 -o empty -e empty clang --target="$target" \
	    -fuse-ld=lld -nostdlib -static -fno-stack-protector -fno-builtin \
	    -O2 -Wall -Wextra -Werror -o rwf \
	    "$(atf_get_srcdir)/linux_rwf.c"
	atf_check -s exit:0 brandelf -t Linux rwf
	./rwf 2>stderr.txt; rc=$?
	cat stderr.txt >&2
	[ $rc -eq 0 ] || atf_fail "exit status $rc"
}
atf_init_test_cases()
{
	atf_add_test_case rwf
}
