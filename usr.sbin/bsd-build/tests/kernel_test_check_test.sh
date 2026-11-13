# SPDX-License-Identifier: BSD-2-Clause
#
# release/scripts/check-kernel-no-dq-test.sh: the check that keeps a kernel
# or module built with the dq(4) test option (options DQ_TEST_OPEN) out of
# package repositories and release media.  The script is installed beside
# this test.  Fixtures are plain files: the check reads bytes, it does not
# parse ELF.

MARKER='@(#)5BSD DQ_TEST_OPEN test kernel: not for publication'
SYMBOL='dq_testopen_bind'
REFUSED='was built with the dq\(4\) test option'

setup()
{
    script="$(atf_get_srcdir)/check-kernel-no-dq-test.sh"
    [ -f "$script" ] || atf_fail 'check-kernel-no-dq-test.sh not installed beside the test'
    mkdir tmp
    # atf_check runs programs, not shell functions.
    cat > check <<SCRIPT
#!/bin/sh
TMPDIR="$PWD/tmp" exec sh "$script" "\$@"
SCRIPT
    chmod +x check
}

# The check leaves nothing behind, whether it passes or refuses.
clean()
{
    [ -z "$(ls -A tmp)" ] || atf_fail "temporary files left behind: $(ls -A tmp)"
}

# tree directory: a staged tree with a clean kernel and module.
tree()
{
    mkdir -p "$1/boot/kernel" "$1/boot/modules" "$1/boot/efi"
    echo 'ELF plain kernel' > "$1/boot/kernel/kernel"
    echo 'ELF plain module' > "$1/boot/kernel/plain.ko"
    echo 'loader text' > "$1/boot/loader.conf"
}

# package repository name tree [member...]: archive members of a tree.
package()
{
    mkdir -p "$1"
    repository=$1 name=$2 from=$3
    shift 3
    tar -cf "$repository/$name" -C "$from" "$@"
}

atf_test_case usage
usage_body()
{
    setup
    atf_check -s exit:2 -o empty -e match:'^usage: ' ./check
    atf_check -s exit:2 -o empty -e match:'^usage: ' ./check stray
    atf_check -s exit:2 -o empty -e match:'usage: ' ./check -x
    tree good
    atf_check -s exit:2 -o empty -e match:'^usage: ' ./check -d good stray
    # There is no override option.
    for flag in -f -n -y; do
        atf_check -s exit:2 -o empty -e match:'usage: ' ./check $flag -d good
    done
    clean
}

atf_test_case staged_tree
staged_tree_body()
{
    setup
    tree good
    atf_check -s exit:0 -o match:'^check-kernel-no-dq-test: 3 kernel and boot files checked' \
        -e empty ./check -d good
    atf_check -s exit:0 -o ignore -e empty ./check -d good/

    # Either signature, in the kernel, a module, or any file under boot.
    for sample in "kernel/kernel:$MARKER" "kernel/kernel:$SYMBOL" \
        "kernel/plain.ko:$SYMBOL" "modules/extra.ko:$MARKER" \
        "kernel/kernel.old:$SYMBOL" "efi/blob:$MARKER" \
        "kernel/zfs.ko.debug:$SYMBOL"; do
        rm -rf bad
        tree bad
        printf 'ELF\0\0%s\0\0tail' "${sample#*:}" > "bad/boot/${sample%%:*}"
        atf_check -s exit:1 -o empty \
            -e match:"staged tree bad: boot/${sample%%:*} $REFUSED" \
            ./check -d bad
    done
    atf_check -s exit:1 -o empty -e match:'There is no' ./check -d bad
    # One bad argument among good ones refuses.
    atf_check -s exit:1 -o empty -e match:"$REFUSED" ./check -d good -d bad
    atf_check -s exit:1 -o empty -e match:"$REFUSED" ./check -d bad -d good

    # Fail closed.
    atf_check -s exit:1 -o empty -e match:'has no boot directory' ./check -d tmp
    atf_check -s exit:1 -o empty -e match:'has no boot directory' ./check -d absent
    mkdir -p nokernel/boot/kernel
    echo m > nokernel/boot/kernel/plain.ko
    atf_check -s exit:1 -o empty -e match:'no kernel under' ./check -d nokernel
    for name in kernel/kernel.gz kernel/plain.ko.xz modules/x.ko.zst; do
        rm -rf packed
        tree packed
        echo packed > "packed/boot/$name"
        atf_check -s exit:1 -o empty \
            -e match:'compressed kernel or module cannot be checked' \
            ./check -d packed
    done
    clean
}

atf_test_case object_directory
object_directory_body()
{
    setup
    mkdir -p obj/modules/usr/src/sys/modules/dq
    echo 'ELF kernel' > obj/kernel
    echo 'ELF kernel full' > obj/kernel.full
    echo 'ELF kernel debug' > obj/kernel.debug
    echo 'ELF module' > obj/modules/usr/src/sys/modules/dq/dq.ko
    # Objects and sources are not kernels: only what is installed counts.
    echo "$SYMBOL" > obj/dq_testopen.o
    atf_check -s exit:0 -o match:' 4 kernel and boot files checked' -e empty \
        ./check -o obj
    for file in kernel kernel.full kernel.debug \
        modules/usr/src/sys/modules/dq/dq.ko; do
        cp -R obj objbad
        printf 'ELF\0%s\0' "$SYMBOL" > "objbad/$file"
        atf_check -s exit:1 -o empty \
            -e match:"kernel build directory objbad: $file $REFUSED" \
            ./check -o objbad
        rm -rf objbad
    done
    atf_check -s exit:1 -o empty -e match:'does not exist' ./check -o absent
    mkdir empty
    atf_check -s exit:1 -o empty -e match:'no kernel in the kernel build directory' \
        ./check -o empty
    clean
}

atf_test_case image_root
image_root_body()
{
    setup
    # A root without a kernel is legitimate.
    mkdir -p root/usr/bin
    echo program > root/usr/bin/program
    atf_check -s exit:0 -o match:' 0 kernel and boot files checked' -e empty \
        ./check -i root
    tree root
    # Nothing is searched twice.
    atf_check -s exit:0 -o match:' 3 kernel and boot files checked' -e empty \
        ./check -i root
    # A kernel or module by name anywhere, anything under boot.
    mkdir -p root/usr/lib/debug/boot/kernel
    printf 'ELF\0%s\0' "$SYMBOL" > root/usr/lib/debug/boot/kernel/kernel.debug
    atf_check -s exit:1 -o empty \
        -e match:"image root root: usr/lib/debug/boot/kernel/kernel.debug $REFUSED" \
        ./check -i root
    rm root/usr/lib/debug/boot/kernel/kernel.debug
    printf '%s' "$MARKER" > root/boot/efi/blob
    atf_check -s exit:1 -o empty -e match:"boot/efi/blob $REFUSED" ./check -i root
    atf_check -s exit:1 -o empty -e match:'does not exist' ./check -i absent
    clean
}

atf_test_case archive
archive_body()
{
    setup
    tree good
    package . boot.tar good boot
    atf_check -s exit:0 -o match:' 3 kernel and boot files checked' -e empty \
        ./check -a boot.tar
    # It need not carry a kernel, and its name does not matter.
    mkdir -p other/boot
    echo text > other/boot/loader.conf
    package . anything other boot
    atf_check -s exit:0 -o match:' 1 kernel and boot files checked' -e empty \
        ./check -a anything
    tree bad
    printf 'ELF\0%s\0' "$SYMBOL" > bad/boot/modules/added.ko
    package . bad.tar bad boot
    atf_check -s exit:1 -o empty \
        -e match:"archive bad.tar: boot/modules/added.ko $REFUSED" \
        ./check -a bad.tar
    atf_check -s exit:1 -o empty -e match:"$REFUSED" ./check -a boot.tar -a bad.tar
    atf_check -s exit:1 -o empty -e match:'archive does not exist' ./check -a absent
    atf_check -s exit:1 -o empty -e match:'archive does not exist' ./check -a good
    echo 'not an archive' > broken
    atf_check -s exit:1 -o empty -e match:'cannot list archive' ./check -a broken
    clean
}

atf_test_case repository
repository_body()
{
    setup
    tree good
    mkdir -p good/usr/lib/debug/boot/kernel good/usr/share
    echo 'ELF debug' > good/usr/lib/debug/boot/kernel/kernel.debug
    echo "text naming $SYMBOL and $MARKER" > good/usr/share/notes
    package repo 5BSD-kernel-1.pkg good boot
    package repo 5BSD-other-1.pkg good usr
    package repo/nested extra.txz good boot/kernel/plain.ko
    echo '{}' > repo/meta.conf
    # Files that are neither kernels nor under boot are not searched.
    atf_check -s exit:0 -o match:' 5 kernel and boot files checked' -e empty \
        ./check -r repo
    atf_check -s exit:0 -o ignore -e empty ./check -r repo/

    # A signature in any archive, at any depth, under any member spelling.
    tree bad
    printf 'ELF\0%s\0' "$MARKER" > bad/boot/kernel/kernel
    for spelling in plain dot absolute; do
        rm -rf badrepo
        cp -R repo badrepo
        case $spelling in
        plain)    tar -cf badrepo/nested/b.tzst -C bad boot ;;
        dot)      (cd bad && tar -cf ../badrepo/b.pkg ./boot) ;;
        absolute) tar -cPf badrepo/b.pkg -s ',^boot,/boot,' -C bad boot ;;
        esac
        atf_check -s exit:1 -o empty \
            -e match:"b\.[a-z]*: boot/kernel/kernel $REFUSED" ./check -r badrepo
    done
    # Outside boot, by name.
    rm -rf badrepo bad
    cp -R repo badrepo
    mkdir -p bad/usr/lib/debug/boot/kernel bad/opt
    printf 'ELF\0%s\0' "$SYMBOL" > bad/usr/lib/debug/boot/kernel/dq.ko.debug
    package badrepo dbg.pkg bad usr
    atf_check -s exit:1 -o empty -e match:"dq.ko.debug $REFUSED" ./check -r badrepo
    rm badrepo/dbg.pkg
    printf 'ELF\0%s\0' "$SYMBOL" > bad/opt/kernel
    package badrepo opt.pkg bad opt
    atf_check -s exit:1 -o empty -e match:"opt/kernel $REFUSED" ./check -r badrepo

    # Fail closed.
    atf_check -s exit:1 -o empty -e match:'repository does not exist' ./check -r absent
    mkdir norepo
    echo '{}' > norepo/meta.conf
    atf_check -s exit:1 -o empty -e match:'no package in repository' ./check -r norepo
    package nokernel other.pkg good usr/share
    atf_check -s exit:1 -o empty -e match:'no kernel in any package' ./check -r nokernel
    rm -rf badrepo
    cp -R repo badrepo
    echo 'not an archive' > badrepo/broken.pkg
    atf_check -s exit:1 -o empty -e match:'cannot list package' ./check -r badrepo
    # A kernel that is a hard link to a member outside the selection
    # cannot be extracted on its own: refused, not passed.
    rm -rf badrepo bad
    cp -R repo badrepo
    mkdir -p bad/boot/kernel bad/usr
    printf 'ELF\0%s\0' "$SYMBOL" > bad/usr/aaa
    ln bad/usr/aaa bad/boot/kernel/kernel
    tar -cf badrepo/link.pkg -C bad usr boot
    atf_check -s exit:1 -o empty -e match:'cannot extract from package' ./check -r badrepo
    # A compressed kernel or module.
    for name in boot/kernel/kernel.gz boot/modules/x.ko.xz usr/lib/kernel.zst; do
        rm -rf badrepo bad
        cp -R repo badrepo
        mkdir -p "bad/${name%/*}"
        echo packed > "bad/$name"
        package badrepo packed.pkg bad "${name%%/*}"
        atf_check -s exit:1 -o empty \
            -e match:'compressed kernel or module cannot be checked' \
            ./check -r badrepo
    done
    # The repository is only read.
    find repo -type f | sort > after
    atf_check -s exit:0 -o inline:'repo/5BSD-kernel-1.pkg\nrepo/5BSD-other-1.pkg\nrepo/meta.conf\nrepo/nested/extra.txz\n' cat after
    clean
}

atf_init_test_cases()
{
    atf_add_test_case usage
    atf_add_test_case staged_tree
    atf_add_test_case object_directory
    atf_add_test_case image_root
    atf_add_test_case archive
    atf_add_test_case repository
}
