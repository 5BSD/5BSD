# SPDX-License-Identifier: BSD-2-Clause
atf_test_case options
options_head()
{
    atf_set descr "Native squeue and Linux io_uring setup policy, ownership, layout, deadlines and request validation"
    atf_set require.arch "amd64 arm64 aarch64"
    atf_set require.progs "cc clang ld.lld brandelf timeout df awk"
    atf_set require.user root
    atf_set timeout 360
}
options_body()
{
    df -T / | awk 'NR == 2 && $2 == "zfs" {ok=1} END {exit !ok}' ||
        atf_fail "requires the disposable ZFS-root VM"
    case "$(uname -m)" in
    amd64) target=x86_64-linux-gnu ;;
    arm64) target=aarch64-linux-gnu ;;
    *) atf_fail "unsupported architecture" ;;
    esac
    kldstat -q -n linux64.ko || atf_check -s exit:0 kldload linux64
    atf_check -s exit:0 cc -pthread -O2 -Wall -Wextra -Werror -o native "$(atf_get_srcdir)/squeue_options.c"
    atf_check -s exit:0 clang --target="$target" -DLINUX_ABI -fuse-ld=lld \
        -nostdlib -static -fno-stack-protector -fno-builtin -O2 \
        -Wall -Wextra -Werror -o linux "$(atf_get_srcdir)/squeue_options.c"
    atf_check -s exit:0 brandelf -t Linux linux
    for abi in native linux; do
        atf_check -s exit:0 -o save:cases.txt ./$abi -l
        [ "$(wc -l <cases.txt | tr -d ' ')" -eq 192 ] || atf_fail "missing cases"
        while read -r name; do
            mkdir "$abi-$name" || atf_fail "mkdir"
            (cd "$abi-$name" && timeout 60 ../$abi "$name") >out.txt 2>&1
            result=$?
            cat out.txt
            [ "$result" -eq 0 ] || atf_fail "$abi/$name: $result"
        done <cases.txt
    done
}
atf_init_test_cases() { atf_add_test_case options; }
