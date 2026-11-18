#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The mandatory kernel options of sys/conf/mandatory-options (AUDIT,
# CAPABILITY_MODE, CAPABILITIES, RACCT, RCTL): the check script that reads
# kernels, the build that refuses a configuration without them, standalone
# module builds that see them, and build-bsd's plan refusals, including a
# world built WITHOUT_AUDIT.  The cases that build or plan need /usr/src.
#

MANDATORY='AUDIT CAPABILITY_MODE CAPABILITIES RACCT RCTL'
FEATURES='audit security_capability_mode security_capabilities racct rctl'

setup()
{
    here=$(atf_get_srcdir)
    check="$here/check-mandatory-kernel.sh"
    ledger="$here/mandatory-options"
    [ -f "$check" ] || atf_fail 'check-mandatory-kernel.sh not installed beside the test'
    [ -f "$ledger" ] || atf_fail 'mandatory-options not installed beside the test'
    # atf_check runs a program, not a shell function.
    printf '#!/bin/sh\nexec sh "%s" -l "%s" "$@"\n' "$check" "$ledger" > check
    chmod +x check
}

need_source()
{
    [ -f /usr/src/Makefile ] && [ -f /usr/src/sys/conf/mandatory-options ] ||
        atf_skip 'DEFERRED_SOURCE_TIER: needs a /usr/src with sys/conf/mandatory-options (vm-provider.sh SRC_IMAGE)'
}

# fake_kernel file feature...: an ELF object defining the kern.features
# sysctl symbols of the features named.
fake_kernel()
{
    out=$1; shift
    : > fake.c
    for f in "$@"; do
        echo "int sysctl___kern_features_$f;" >> fake.c
    done
    echo 'int fake_kernel_marker;' >> fake.c
    atf_check -s exit:0 -o empty -e empty cc -c -o "$out" fake.c
}

atf_test_case ledger_list
ledger_list_head()
{
    atf_set descr 'The ledger lists the five mandatory options'
}
ledger_list_body()
{
    setup
    atf_check -s exit:0 -o inline:"AUDIT\nCAPABILITY_MODE\nCAPABILITIES\nRACCT\nRCTL\n" \
        -e empty ./check -L
}

atf_test_case ledger_refused
ledger_refused_head()
{
    atf_set descr 'A missing, malformed, empty or linked ledger is a refusal'
}
ledger_refused_body()
{
    setup
    fake_kernel kernel $FEATURES
    atf_check -s exit:1 -o empty -e match:'cannot be read' \
        sh "$check" -l "$PWD/no-such-ledger" -k kernel
    printf 'AUDIT opt_global.h\n' > bad
    atf_check -s exit:1 -o empty -e match:'malformed' sh "$check" -l bad -k kernel
    printf '# nothing\n' > empty
    atf_check -s exit:1 -o empty -e match:'malformed' sh "$check" -l empty -k kernel
    printf 'AUDIT opt_global.h audit\nAUDIT opt_global.h audit\n' > dup
    atf_check -s exit:1 -o empty -e match:'duplicate option AUDIT' \
        sh "$check" -l dup -k kernel
    ln -s "$ledger" link
    atf_check -s exit:1 -o empty -e match:'symbolic link' sh "$check" -l link -k kernel
}

atf_test_case kernel_checked
kernel_checked_head()
{
    atf_set descr 'A kernel with every feature passes; one without any one is refused'
    atf_set require.progs 'cc readelf strip'
}
kernel_checked_body()
{
    setup
    fake_kernel kernel $FEATURES
    atf_check -s exit:0 -o match:'1 kernel\(s\) carry AUDIT CAPABILITY_MODE CAPABILITIES RACCT RCTL' \
        -e empty ./check -k kernel
    set -- $MANDATORY
    for f in $FEATURES; do
        option=$1; shift
        fake_kernel without $(echo $FEATURES | tr ' ' '\n' | grep -vx "$f")
        atf_check -s exit:1 -o empty -e match:"built without options $option\$" \
            ./check -k without
    done
    # A kernel with other kern.features but none of the ledger's.
    fake_kernel none compat_freebsd11
    atf_check -s exit:1 -o empty \
        -e match:'built without options AUDIT CAPABILITY_MODE CAPABILITIES RACCT RCTL$' \
        ./check -k none
    # No kern.features symbol at all, or no symbol table: nothing can be
    # concluded.
    fake_kernel nofeatures
    atf_check -s exit:1 -o empty -e match:'no symbol table' ./check -k nofeatures
    cp kernel stripped
    atf_check -s exit:0 strip stripped
    atf_check -s exit:1 -o empty -e match:'no symbol table' ./check -k stripped
    printf 'not an elf file\n' > text
    atf_check -s exit:1 -o empty -e match:'cannot be read|no symbol table' ./check -k text
}

atf_test_case trees_and_archives
trees_and_archives_head()
{
    atf_set descr 'Object, staged and image trees, archives and repositories'
    atf_set require.progs 'cc readelf tar'
}
trees_and_archives_body()
{
    setup
    mkdir -p obj/GOOD stage/boot/kernel stage/boot/kernel.old image/boot/kernel \
        noboot repo/All bad/boot/kernel
    fake_kernel obj/GOOD/kernel $FEATURES
    cp obj/GOOD/kernel stage/boot/kernel/kernel
    cp obj/GOOD/kernel stage/boot/kernel.old/kernel
    cp obj/GOOD/kernel image/boot/kernel/kernel
    fake_kernel bad/boot/kernel/kernel audit racct rctl
    atf_check -s exit:0 -o match:'1 kernel' -e empty ./check -o obj/GOOD
    atf_check -s exit:0 -o match:'2 kernel' -e empty ./check -d stage
    atf_check -s exit:0 -o match:'1 kernel' -e empty ./check -i image
    # An image root may carry no kernel; a staged tree may not.
    atf_check -s exit:0 -o match:'0 kernel' -e empty ./check -i noboot
    atf_check -s exit:1 -o empty -e match:'no boot directory' ./check -d noboot
    atf_check -s exit:1 -o empty \
        -e match:'built without options CAPABILITY_MODE CAPABILITIES$' ./check -d bad
    # Every argument is checked.
    atf_check -s exit:1 -o empty -e match:'built without' ./check -d stage -d bad
    # Archives and repositories: every boot/*/kernel member.
    atf_check -s exit:0 tar -cf repo/All/kernel-good.pkg -C stage boot
    atf_check -s exit:0 tar -cf good.tar -C stage boot
    atf_check -s exit:0 -o match:'2 kernel' -e empty ./check -a good.tar
    atf_check -s exit:0 -o match:'2 kernel' -e empty ./check -r repo
    atf_check -s exit:0 tar -cf repo/All/kernel-bad.pkg -C bad boot
    atf_check -s exit:1 -o empty -e match:'built without' ./check -r repo
    atf_check -s exit:0 tar -cf nokernel.tar fake.c
    atf_check -s exit:1 -o empty -e match:'no boot/\*/kernel member' ./check -a nokernel.tar
    mkdir emptyrepo
    atf_check -s exit:1 -o empty -e match:'no kernel in any package' ./check -r emptyrepo
}

atf_test_case source_agrees
source_agrees_head()
{
    atf_set descr 'The ledger, kern_mandatory.c and every DEFAULTS name the same options'
}
source_agrees_body()
{
    setup
    need_source
    echo $MANDATORY | tr ' ' '\n' > expected
    atf_check -s exit:0 -o file:expected -e empty \
        sh /usr/src/release/scripts/check-mandatory-kernel.sh -L
    atf_check -s exit:0 -o empty cmp -s /usr/src/sys/conf/mandatory-options "$ledger"
    sed -n 's/^#ifndef \([A-Z_]*\)$/\1/p' /usr/src/sys/kern/kern_mandatory.c > mandatory.c.list
    atf_check -s exit:0 -o empty diff -u expected mandatory.c.list
    atf_check -s exit:0 -o match:'^kern/kern_mandatory\.c[[:space:]]+standard$' \
        grep '^kern/kern_mandatory\.c' /usr/src/sys/conf/files
    for arch in amd64 arm64 riscv; do
        awk '$1 == "options" { print $2 }' /usr/src/sys/$arch/conf/DEFAULTS |
            grep -xE "$(echo $MANDATORY | tr ' ' '|')" > defaults.$arch
        atf_check -s exit:0 -o empty diff -u expected defaults.$arch
    done
}

atf_test_case module_opt_global
module_opt_global_head()
{
    atf_set descr 'A standalone module build defines every mandatory option'
    atf_set require.progs 'make'
}
module_opt_global_body()
{
    setup
    need_source
    atf_check -s exit:0 -o ignore -e ignore env MAKEOBJDIRPREFIX="$PWD/obj" \
        make -m /usr/src/share/mk -C /usr/src/sys/modules/mqueue opt_global.h
    header=$(find "$PWD/obj" -name opt_global.h)
    [ -n "$header" ] || atf_fail 'no opt_global.h was made'
    for option in $MANDATORY; do
        atf_check -s exit:0 -o ignore grep -E "^#define[[:space:]]+$option[[:space:]]+1\$" "$header"
    done
}

atf_test_case nooptions_fails_build
nooptions_fails_build_head()
{
    atf_set descr 'A configuration without any one mandatory option does not build'
    atf_set require.progs 'cc config make'
    atf_set timeout 600
}
nooptions_fails_build_body()
{
    setup
    need_source
    conf=/usr/src/sys/$(uname -m)/conf
    [ -d "$conf" ] || atf_skip "no kernel configurations for $(uname -m)"
    work=$PWD
    for option in $MANDATORY ""; do
        name=NO${option:-NE}
        printf 'include GENERIC\nident %s\n' $name > $name.conf
        [ -z "$option" ] || printf 'nooptions %s\n' $option >> $name.conf
        mkdir $name
        # config(8) finds the source tree from the configuration directory;
        # the compile directory is the work directory's, since /usr/src may
        # be read-only.
        (cd "$conf" && config -I "$conf" -d "$work/$name" "$work/$name.conf") \
            > $name.config 2>&1 || atf_fail "config $name: $(cat $name.config)"
        atf_check -s exit:0 -o ignore grep -q 'kern_mandatory\.o' $name/Makefile
        if [ -n "$option" ]; then
            atf_check -s not-exit:0 -o ignore \
                -e match:"5BSD kernels require options $option " \
                env MAKEFLAGS= make -m /usr/src/share/mk -C $name kern_mandatory.o
        else
            atf_check -s exit:0 -o ignore -e ignore \
                env MAKEFLAGS= make -m /usr/src/share/mk -C $name kern_mandatory.o
        fi
    done
}

atf_test_case world_without_audit
world_without_audit_head()
{
    atf_set descr 'A world built WITHOUT_AUDIT is refused'
    atf_set require.progs 'make'
}
world_without_audit_body()
{
    setup
    need_source
    # No object directory: reading a variable must not create one, under
    # /usr/obj or anywhere else, nor report doing so on stderr.
    atf_check -s exit:0 -o inline:'yes\n' -e empty \
        env WITHOUT_AUTO_OBJ=yes MAKEOBJDIRPREFIX="$PWD/obj" \
        make -m /usr/src/share/mk -C /usr/src/usr.bin/id -V MK_AUDIT
    # make reports where it stopped on stdout; no value is printed.
    atf_check -s not-exit:0 -o not-match:'^(yes|no)$' \
        -e match:'WITHOUT_AUDIT is refused in 5BSD: BSM audit is mandatory' \
        env WITHOUT_AUTO_OBJ=yes MAKEOBJDIRPREFIX="$PWD/obj" \
        make -m /usr/src/share/mk -C /usr/src/usr.bin/id -V MK_AUDIT WITHOUT_AUDIT=yes
    [ ! -e obj ] || atf_fail 'make -V created an object directory'
}

atf_test_case plan_refusals
plan_refusals_head()
{
    atf_set descr 'build-bsd refuses nooptions of a mandatory option and WITHOUT_AUDIT'
}
plan_refusals_body()
{
    setup
    need_source
    tool=$(atf_config_get bsd_build /usr/sbin/build-bsd)
    [ -f "$tool" ] || atf_fail 'build-bsd not installed'
    mkdir kconf
    for option in $MANDATORY; do
        printf 'include GENERIC\nident NO%s\nnooptions %s\n' $option $option \
            > kconf/NO$option
        atf_check -s exit:1 -o empty \
            -e match:"removes options $option \\(nooptions\\), which every 5BSD kernel requires" \
            "$tool" plan kernel --kernel NO$option --kernel-dir "$PWD/kconf"
        atf_check -s exit:1 -o empty -e match:"removes options $option" \
            "$tool" plan packages --kernel NO$option --kernel-dir "$PWD/kconf"
    done
    # Reached through an include, too.
    printf 'include NORACCT\nident VIA\n' > kconf/VIA
    atf_check -s exit:1 -o empty -e match:'removes options RACCT' \
        "$tool" plan kernel --kernel VIA --kernel-dir "$PWD/kconf"
    atf_check -s exit:0 -o match:'kernel-mandatory-option-configuration=complete kernel-mandatory-option-binary-check=not-performed$' \
        -e empty "$tool" plan kernel --kernel GENERIC
    # A kernel-identity-only profile compiles no ports, so the packages plan
    # needs no ports checkout.
    printf 'no-hardware-ports # kernel identity only\n' > none
    atf_check -s exit:0 -o match:'"kernel_mandatory_option_configuration":"complete","kernel_mandatory_option_binary_check":"requested"' \
        -e empty "$tool" plan packages --kernel GENERIC --format json \
        --hardware-profile "$PWD/none" --ports /nonexistent/ports
    atf_check -s exit:0 -o match:'kernel-mandatory-option-configuration=not-performed' \
        -e empty "$tool" plan world
    printf 'WITHOUT_AUDIT=yes\n' > src.conf
    for action in build world stage packages; do
        atf_check -s exit:1 -o empty \
            -e match:'defines WITHOUT_AUDIT: BSM audit is mandatory in 5BSD' \
            "$tool" plan $action --src-conf "$PWD/src.conf"
    done
    printf '# WITHOUT_AUDIT=yes\nWITH_FOO=yes\n' > commented.conf
    atf_check -s exit:0 -o ignore -e empty \
        "$tool" plan build --src-conf "$PWD/commented.conf"
}

atf_init_test_cases()
{
    atf_add_test_case ledger_list
    atf_add_test_case ledger_refused
    atf_add_test_case kernel_checked
    atf_add_test_case trees_and_archives
    atf_add_test_case source_agrees
    atf_add_test_case module_opt_global
    atf_add_test_case nooptions_fails_build
    atf_add_test_case world_without_audit
    atf_add_test_case plan_refusals
}
