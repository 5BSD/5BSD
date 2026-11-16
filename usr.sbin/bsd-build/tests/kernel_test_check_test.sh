# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# release/scripts/check-test-kernel.sh: the check that keeps a kernel or
# module built with a test-kernel option (a row of sys/conf/test-options,
# for example options DQ_TEST_OPEN, the dq(4) test option) out of
# package repositories and release media.  The script is installed beside
# this test.  Fixtures are plain files: the check reads bytes, it does not
# parse ELF.  package_format writes archives the way pkg(8) does; no case
# reads a published repository.

MARKER='@(#)5BSD DQ_TEST_OPEN test kernel: not for publication'
SYMBOL='dq_testopen_bind'
REFUSED='was built with options DQ_TEST_OPEN, a test-kernel option'

# The ledger is installed beside the test, as the script is.  check runs
# the script with it; raw runs it as it is, with its own default ledger.
setup()
{
    script="$(atf_get_srcdir)/check-test-kernel.sh"
    ledger="$(atf_get_srcdir)/test-options"
    [ -f "$script" ] || atf_fail 'check-test-kernel.sh not installed beside the test'
    [ -f "$ledger" ] || atf_fail 'the test-options ledger not installed beside the test'
    mkdir tmp
    # atf_check runs programs, not shell functions.
    cat > check <<SCRIPT
#!/bin/sh
TMPDIR="$PWD/tmp" exec sh "$script" -l "$ledger" "\$@"
SCRIPT
    cat > raw <<SCRIPT
#!/bin/sh
TMPDIR="$PWD/tmp" exec sh "\$@"
SCRIPT
    chmod +x check raw
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
    # Listing checks nothing, and nothing is checked with it.
    atf_check -s exit:2 -o empty -e match:'usage: ' ./check -L -d good
    atf_check -s exit:2 -o empty -e match:'usage: ' ./check -L stray
    clean
}

atf_test_case ledger
ledger_head()
{
    atf_set descr 'Every ledger row is a signature; a ledger that cannot be read whole refuses'
}
ledger_body()
{
    setup
    tree good
    # The installed ledger lists what it lists, and its first row is the
    # dq(4) test option.
    atf_check -s exit:0 -o save:rows -e empty ./check -L
    grep -v -e '^#' -e '^$' "$ledger" > expected
    atf_check -s exit:0 -o empty -e empty cmp rows expected
    atf_check -s exit:0 -o match:'^DQ_TEST_OPEN\|live\|GENERIC-TEST\|dq_testopen_\|' \
        head -n 1 rows

    # A private ledger: a live row, a reserved row, a row without prefix.
    cat > private <<'EOF'
# comment
LG3_LIVE|live|GENERIC-TEST|lg3_live_|@(#)5BSD LG3_LIVE test kernel: not for publication|debug.lg3.knob

LG3_RESERVED|reserved|-|-|@(#)5BSD LG3_RESERVED measurement kernel: not for publication|-
EOF
    atf_check -s exit:0 -o match:'^check-test-kernel: 3 kernel and boot files checked, no test-kernel option$' \
        -e empty ./check -l "$PWD/private" -d good
    # -l counts wherever it stands; the last one wins.
    atf_check -s exit:0 -o ignore -e empty ./check -d good -l "$PWD/private"
    for sample in "LG3_LIVE:lg3_live_symbol" \
        "LG3_LIVE:@(#)5BSD LG3_LIVE test kernel: not for publication" \
        "LG3_RESERVED:@(#)5BSD LG3_RESERVED measurement kernel: not for publication"; do
        rm -rf bad
        tree bad
        printf 'ELF\0%s\0' "${sample#*:}" > bad/boot/kernel/kernel
        atf_check -s exit:1 -o empty \
            -e match:"boot/kernel/kernel was built with options ${sample%%:*}, a test-kernel option" \
            ./check -l "$PWD/private" -d bad
    done
    # The dq(4) signatures are not in the private ledger.
    rm -rf bad
    tree bad
    printf 'ELF\0%s\0' "$MARKER" > bad/boot/kernel/kernel
    atf_check -s exit:0 -o ignore -e empty ./check -l "$PWD/private" -d bad
    atf_check -s exit:1 -o empty -e match:"$REFUSED" ./check -d bad

    # Fail closed: no ledger, an empty one, and every malformed row.
    atf_check -s exit:1 -o empty -e match:'ledger cannot be read' \
        ./check -l "$PWD/absent" -d good
    atf_check -s exit:1 -o empty -e match:'ledger cannot be read' \
        ./check -l "$PWD/tmp" -d good
    # The installed script has no source tree around it: no default ledger.
    atf_check -s exit:1 -o empty -e match:'ledger cannot be read' \
        ./raw "$script" -d good
    printf '# only a comment\n\n' > empty
    atf_check -s exit:1 -o empty -e match:'malformed: no rows' \
        ./check -l "$PWD/empty" -d good
    m='test kernel: not for publication'
    for row in \
        "A|live|-|-|@(#)5BSD A $m" \
        "A|live|-|-|@(#)5BSD A $m|-|extra" \
        "a|live|-|-|@(#)5BSD a $m|-" \
        "A|maybe|-|-|@(#)5BSD A $m|-" \
        "A|live|bad config|-|@(#)5BSD A $m|-" \
        "A|live|-|nounderscore|@(#)5BSD A $m|-" \
        "A|live|-|-|@(#)5BSD B $m|-" \
        "A|live|-|-|5BSD A $m|-" \
        "A|live|-|-|@(#)5BSD A $m|Knob" \
        "A|reserved|-|a_|@(#)5BSD A $m|-" \
        "A|live|-|-|@(#)5BSD A $m|-
A|live|-|-|@(#)5BSD A $m|-"; do
        printf '%s\n' "$row" > broken
        atf_check -s exit:1 -o empty -e match:'ledger .* is malformed' \
            ./check -l "$PWD/broken" -d good
        atf_check -s exit:1 -o empty -e match:'ledger .* is malformed' \
            ./check -l "$PWD/broken" -L
    done
    clean
}

atf_test_case staged_tree
staged_tree_body()
{
    setup
    tree good
    atf_check -s exit:0 -o match:'^check-test-kernel: 3 kernel and boot files checked' \
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
repository_head()
{
    # Every archive is listed and extracted: minutes on a small guest.
    atf_set timeout 1800
}
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

atf_test_case package_store
package_store_body()
{
    setup
    # The package store of release media: it may be empty and need not
    # carry a kernel, but every archive in it is read.
    mkdir store
    atf_check -s exit:0 -o match:' 0 kernel and boot files checked' -e empty \
        ./check -p store
    tree good
    mkdir -p good/usr/share
    echo text > good/usr/share/notes
    package store other.pkg good usr
    atf_check -s exit:0 -o match:' 0 kernel and boot files checked' -e empty \
        ./check -p store
    package store/repos/base 5BSD-kernel-1.pkg good boot
    atf_check -s exit:0 -o match:' 3 kernel and boot files checked' -e empty \
        ./check -p store
    tree bad
    printf 'ELF\0%s\0' "$MARKER" > bad/boot/modules/stray.ko
    package store/repos/hardware stray.pkg bad boot
    atf_check -s exit:1 -o empty \
        -e match:"stray.pkg: boot/modules/stray.ko $REFUSED" ./check -p store
    atf_check -s exit:1 -o empty -e match:'repository does not exist' ./check -p absent
    rm store/repos/hardware/stray.pkg
    echo 'not an archive' > store/broken.pkg
    atf_check -s exit:1 -o empty -e match:'cannot list package' ./check -p store
    clean
}

atf_test_case package_format
package_format_body()
{
    setup
    # A package as pkg(8) writes it: zstd, manifests first, absolute
    # member names, modules beside the kernel, a debug package apart.
    tree good
    mkdir -p good/usr/lib/debug/boot/kernel
    echo 'ELF debug' > good/usr/lib/debug/boot/kernel/kernel.debug
    echo '{"name":"5BSD-kernel-generic"}' > good/+COMPACT_MANIFEST
    echo '{"name":"5BSD-kernel-generic","files":{}}' > good/+MANIFEST
    pack()
    {
        mkdir -p "$1"
        (cd "$3" && tar --zstd -cPf "../$1/$2" -s ',^boot,/boot,' \
            -s ',^usr,/usr,' +COMPACT_MANIFEST +MANIFEST "$4") ||
            atf_fail 'cannot write a zstd package'
    }
    pack repo 5BSD-kernel-generic-1.pkg good boot
    pack repo 5BSD-kernel-generic-dbg-1.pkg good usr
    atf_check -s exit:0 -o match:'^/boot/kernel/kernel$' -e ignore \
        tar -tf repo/5BSD-kernel-generic-1.pkg
    atf_check -s exit:0 -o match:' 4 kernel and boot files checked' -e empty \
        ./check -r repo
    for sample in boot/kernel/kernel boot/kernel/plain.ko \
        usr/lib/debug/boot/kernel/kernel.debug; do
        rm -rf bad badrepo
        cp -R good bad
        cp -R repo badrepo
        printf 'ELF\0\0%s\0\0tail' "$MARKER" > "bad/$sample"
        case $sample in
        boot/*) pack badrepo 5BSD-kernel-generic-1.pkg bad boot ;;
        *)      pack badrepo 5BSD-kernel-generic-dbg-1.pkg bad usr ;;
        esac
        atf_check -s exit:1 -o empty -e match:"\.pkg: $sample $REFUSED" \
            ./check -r badrepo
    done
    clean
}

atf_test_case odd_names
odd_names_body()
{
    setup
    tree good
    package repo 5BSD-kernel-1.pkg good boot
    # A name with a space is read like any other.
    tree bad
    printf 'ELF\0%s\0' "$SYMBOL" > 'bad/boot/modules/two words.ko'
    package repo spaced.pkg bad boot
    atf_check -s exit:1 -o empty -e match:"two words.ko $REFUSED" ./check -r repo
    rm repo/spaced.pkg
    atf_check -s exit:1 -o empty -e match:"two words.ko $REFUSED" ./check -d bad
    # A member name that tar(1) reads as a pattern or an option either
    # extracts under its own name and is searched, or is refused: with a
    # signature in it, it never passes.
    for name in 'a[b].ko' 'a*.ko' 'a?.ko' '-C x.ko' 'back\slash.ko'; do
        rm -rf bad
        mkdir -p bad/boot/modules
        printf 'ELF\0%s\0' "$SYMBOL" > "bad/boot/modules/$name"
        tar -cf repo/odd.pkg -C bad boot
        atf_check -s exit:1 -o empty -e ignore ./check -r repo
        atf_check -s exit:1 -o empty -e ignore ./check -a repo/odd.pkg
        atf_check -s exit:1 -o empty -e match:"$REFUSED" ./check -i bad
    done
    # A pattern that would also select a clean member does not hide the
    # one with the signature.
    rm -rf bad
    mkdir -p bad/boot/modules
    echo clean > 'bad/boot/modules/a*.ko'
    printf 'ELF\0%s\0' "$SYMBOL" > bad/boot/modules/abc.ko
    tar -cf repo/odd.pkg -C bad boot
    atf_check -s exit:1 -o empty -e match:"abc.ko $REFUSED" ./check -r repo
    clean
}

atf_test_case symbolic_links
symbolic_links_body()
{
    setup
    tree good
    package repo 5BSD-kernel-1.pkg good boot

    # A directory argument that is itself a link is read.
    ln -s good goodlink
    ln -s repo repolink
    atf_check -s exit:0 -o match:' 3 kernel and boot files checked' -e empty \
        ./check -d goodlink
    atf_check -s exit:0 -o match:' 3 kernel and boot files checked' -e empty \
        ./check -i goodlink
    atf_check -s exit:0 -o match:' 3 kernel and boot files checked' -e empty \
        ./check -r repolink
    mkdir -p obj
    echo 'ELF kernel' > obj/kernel
    ln -s obj objlink
    atf_check -s exit:0 -o match:' 1 kernel and boot files checked' -e empty \
        ./check -o objlink
    tree bad
    printf 'ELF\0%s\0' "$SYMBOL" > bad/boot/kernel/kernel
    ln -s bad badlink
    atf_check -s exit:1 -o empty -e match:"$REFUSED" ./check -d badlink
    atf_check -s exit:1 -o empty -e match:"$REFUSED" ./check -i badlink
    # A boot directory that is a link inside the tree is read; one that
    # leaves the tree is refused.
    mkdir -p pool/bootpool
    tree pool/bootpool
    ln -s bootpool/boot pool/boot
    atf_check -s exit:0 -o match:' 3 kernel and boot files checked' -e empty \
        ./check -d pool
    mkdir away
    ln -s ../good/boot away/boot
    atf_check -s exit:1 -o empty -e match:'boot is a link that leaves' \
        ./check -d away
    atf_check -s exit:1 -o empty -e match:'boot is a link that leaves' \
        ./check -i away

    # A link to an archive is read through; a dangling one is refused.
    package elsewhere bad.pkg bad boot
    cp -R repo linkrepo
    ln -s ../elsewhere/bad.pkg linkrepo/linked.pkg
    atf_check -s exit:1 -o empty -e match:"linked.pkg: boot/kernel/kernel $REFUSED" \
        ./check -r linkrepo
    rm linkrepo/linked.pkg
    ln -s ../absent.pkg linkrepo/linked.pkg
    atf_check -s exit:1 -o empty -e match:'does not lead to an archive' \
        ./check -r linkrepo
    atf_check -s exit:1 -o empty -e match:'does not lead to an archive' \
        ./check -p linkrepo

    # In a tree: a link with a kernel or module name is read through.
    mkdir -p root/usr/libexec root/boot/kernel
    echo 'ELF kernel' > root/boot/kernel/kernel
    printf 'ELF\0%s\0' "$SYMBOL" > root/usr/libexec/hidden
    ln -s ../../usr/libexec/hidden root/boot/kernel/extra.ko
    atf_check -s exit:1 -o empty -e match:"boot/kernel/extra.ko $REFUSED" \
        ./check -d root
    atf_check -s exit:1 -o empty -e match:"boot/kernel/extra.ko $REFUSED" \
        ./check -i root
    # An absolute target is taken inside the root.
    rm root/boot/kernel/extra.ko
    ln -s /usr/libexec/hidden root/boot/kernel/extra.ko
    atf_check -s exit:1 -o empty -e match:"boot/kernel/extra.ko $REFUSED" \
        ./check -d root
    atf_check -s exit:1 -o empty -e match:"boot/kernel/extra.ko $REFUSED" \
        ./check -i root
    # With a clean target it passes and is counted once.
    echo 'ELF clean' > root/usr/libexec/hidden
    atf_check -s exit:0 -o match:' 2 kernel and boot files checked' -e empty \
        ./check -d root
    # A kernel-named link that leads nowhere, or out of the tree.
    rm root/boot/kernel/extra.ko
    ln -s /absent root/boot/kernel/extra.ko
    atf_check -s exit:1 -o empty -e match:'does not lead to a file' ./check -d root
    atf_check -s exit:1 -o empty -e match:'does not lead to a file' ./check -i root
    rm root/boot/kernel/extra.ko
    ln -s ../../../good/boot/kernel/plain.ko root/boot/kernel/extra.ko
    atf_check -s exit:1 -o empty -e match:'leaves the tree' ./check -d root
    atf_check -s exit:1 -o empty -e match:'leaves the tree' ./check -i root
    rm root/boot/kernel/extra.ko
    # Other links under boot: a dangling one and one to a file are not
    # followed; a directory inside boot is read where it is; a directory
    # outside boot is refused.
    ln -s /tmp/bsdinstall_etc/absent root/boot/dangling
    ln -s kernel root/boot/kernel.link
    mkdir root/boot/efi
    ln -s efi root/boot/msdos
    atf_check -s exit:0 -o match:' 1 kernel and boot files checked' -e empty \
        ./check -d root
    atf_check -s exit:0 -o match:' 1 kernel and boot files checked' -e empty \
        ./check -i root
    mkdir -p root/usr/modules
    printf 'ELF\0%s\0' "$SYMBOL" > root/usr/modules/renamed
    ln -s ../usr/modules root/boot/modules
    atf_check -s exit:1 -o empty -e match:'link to a directory that is not read' \
        ./check -d root
    atf_check -s exit:1 -o empty -e match:'link to a directory that is not read' \
        ./check -i root

    # In a kernel build directory links are as the host resolves them:
    # the tree is full of links into the sources, which are not read.
    mkdir -p src/sys
    echo "source naming $SYMBOL" > src/sys/kernel.h
    ln -s ../src/sys obj/@
    ln -s ../src/sys obj/machine
    atf_check -s exit:0 -o match:' 1 kernel and boot files checked' -e empty \
        ./check -o obj
    printf 'ELF\0%s\0' "$SYMBOL" > src/built.ko
    ln -s ../src/built.ko obj/linked.ko
    atf_check -s exit:1 -o empty -e match:"linked.ko $REFUSED" ./check -o obj

    # In an archive: a kernel-named link must lead to a member that is
    # itself checked.
    rm -rf bad
    mkdir -p bad/boot/kernel bad/usr/libexec
    printf 'ELF\0%s\0' "$SYMBOL" > bad/usr/libexec/hidden
    ln -s ../../usr/libexec/hidden bad/boot/kernel/kernel
    tar -cf linked.tar -C bad boot usr
    atf_check -s exit:1 -o empty -e match:'link to a member that is not checked' \
        ./check -a linked.tar
    rm bad/boot/kernel/kernel
    ln -s /usr/libexec/hidden bad/boot/kernel/kernel
    tar -cf linked.tar -C bad boot usr
    atf_check -s exit:1 -o empty -e match:'link to a member that is not checked' \
        ./check -a linked.tar
    # One that leads to a checked member passes; the member is read.
    rm -rf bad
    mkdir -p bad/boot/kernel bad/boot/kernel.prev
    echo 'ELF kernel' > bad/boot/kernel.prev/kernel
    ln -s ../kernel.prev/kernel bad/boot/kernel/kernel
    tar -cf linked.tar -C bad boot
    atf_check -s exit:0 -o match:' 1 kernel and boot files checked' -e empty \
        ./check -a linked.tar
    printf 'ELF\0%s\0' "$SYMBOL" > bad/boot/kernel.prev/kernel
    tar -cf linked.tar -C bad boot
    atf_check -s exit:1 -o empty -e match:"boot/kernel.prev/kernel $REFUSED" \
        ./check -a linked.tar
    clean
}

atf_init_test_cases()
{
    atf_add_test_case usage
    atf_add_test_case ledger
    atf_add_test_case staged_tree
    atf_add_test_case object_directory
    atf_add_test_case image_root
    atf_add_test_case archive
    atf_add_test_case repository
    atf_add_test_case package_store
    atf_add_test_case package_format
    atf_add_test_case odd_names
    atf_add_test_case symbolic_links
}
