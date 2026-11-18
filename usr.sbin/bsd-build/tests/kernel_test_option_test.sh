# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# The test-kernel options and publication (design D346, D352; the ledger,
# sys/conf/test-options, from test-relax-switch slice A).
#
# Everything here is sh: the cases run where no Python exists.  The
# publication recipe is exercised from a private copy of
# release/Makefile.hardware and its check scripts installed beside this
# test, never from /usr/src and never towards /usr/obj/usr/src/repo.

MARKER='@(#)5BSD DQ_TEST_OPEN test kernel: not for publication'
REFUSAL='carries options DQ_TEST_OPEN'

setup()
{
    tool=$(atf_config_get bsd_build /usr/sbin/build-bsd)
    [ -f "$tool" ] || atf_fail 'build-bsd not installed'
    [ -f /usr/src/Makefile ] || atf_skip 'DEFERRED_SOURCE_TIER: source build frontend requires /usr/src (vm-provider.sh SRC_IMAGE)'
    here=$(atf_get_srcdir)
    check="$here/check-test-kernel.sh"
    [ -f "$check" ] || atf_fail 'check-test-kernel.sh not installed beside the test'
    # atf_check runs programs, not shell functions.
    # A package plan needs a hardware profile and a ports checkout; the
    # refusal under test comes before either is looked at.
    mkdir -p ports/Mk ports/distfiles
    : > ports/Mk/bsd.port.mk
    printf 'graphics/drm-kmod\n' > profile
    cat > plan <<SCRIPT
#!/bin/sh
case \$1 in
packages|build)
    set -- "\$@" --hardware-profile "$PWD/profile" --ports "$PWD/ports" ;;
esac
[ -n "\${NO_KERNEL_DIR-}" ] || set -- "\$@" --kernel-dir "$PWD/conf"
exec "$tool" plan "\$@"
SCRIPT
    chmod +x plan
}

# A private source tree holding only the publication recipe.
private_tree()
{
    mkdir -p src/release/scripts src/sys/conf
    cp "$here/Makefile.hardware" src/release/Makefile.hardware
    for script in "$here"/check-*.sh; do
        cp "$script" src/release/scripts/
    done
    cp "$here/test-options" src/sys/conf/test-options
    cp "$here/mandatory-options" src/sys/conf/mandatory-options
    # pkg stands in for pkg(8): it answers the package ABI question
    # Makefile.hardware asks when it is read, and every other call succeeds.
    cat > pkg <<'SCRIPT'
#!/bin/sh
case "$*" in
*"config ABI") echo "FreeBSD:16:$(uname -p)" ;;
esac
exit 0
SCRIPT
    chmod +x pkg
    # atf_check runs programs, not shell functions.
    # HARDWARE_BUILDER stands in for the hardware build and check program
    # (default: one that fails).
    cat > recipe <<SCRIPT
#!/bin/sh
exec make -C "$PWD/src" -f release/Makefile.hardware \\
    PKG_CMD="$PWD/pkg" HARDWARE_PYTHON="\${HARDWARE_BUILDER:-/usr/bin/false}" \\
    BASE_REPOSITORY="$PWD/base" HARDWARE_REPO="$PWD/hardware" \\
    COMPLETE_REPOSITORY="$PWD/published/complete" "\$@"
SCRIPT
    chmod +x recipe
}


# kernel_package repository name content [feature...]: a package holding
# one kernel, an ELF object carrying the string content and the kern.features
# symbols check-mandatory-kernel.sh looks for: those named, or by default
# every one the mandatory-option ledger lists.
kernel_package()
{
    repository=$1 name=$2 content=$3
    shift 3
    [ $# -gt 0 ] || set -- $(awk '!/^#/ && NF == 3 { print $3 }' \
        "$here/mandatory-options")
    mkdir -p "$repository" pkgroot/boot/kernel
    printf 'const char kernel_content[] = "%s";\n' "$content" > kernel.c
    for feature in "$@"; do
        echo "int sysctl___kern_features_$feature;" >> kernel.c
    done
    cc -c -o pkgroot/boot/kernel/kernel kernel.c ||
        atf_fail "cannot compile the $name kernel"
    tar -cf "$repository/$name" -C pkgroot boot
    rm -rf pkgroot kernel.c
}

# A base repository the malloc(3) check accepts.
clibs_package()
{
    mkdir -p "$1" pkgroot/lib
    echo 'not a debug libc' > pkgroot/lib/libc.so.7
    tar -cf "$1/5BSD-clibs-1.pkg" -C pkgroot lib
    rm -rf pkgroot
}

# configuration name lines...: a kernel configuration in ./conf.
configuration()
{
    mkdir -p conf
    name=$1
    shift
    printf '%s\n' "$@" > "conf/$name"
}


atf_test_case plan_option_configuration
plan_option_configuration_head()
{
    atf_set descr 'A package plan for a configuration carrying the dq test option is refused'
}
plan_option_configuration_body()
{
    setup
    configuration LG2OPTION 'include GENERIC' 'ident LG2OPTION' \
        'options 	DQ_TEST_OPEN'
    atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
        ./plan packages --kernel LG2OPTION
    atf_check -s exit:1 -o empty -e match:'no override' \
        ./plan build --kernel LG2OPTION
    atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
        ./plan media --kernel LG2OPTION
    atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
        ./plan packages --kernel LG2OPTION --format json
    # No environment or option lifts it.
    atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
        env ALLOW_DEBUG_MALLOC=yes "$tool" plan packages --kernel LG2OPTION \
        --kernel-dir "$PWD/conf" --build-profile development \
        --allow-debug-publication
}

atf_test_case plan_option_spellings
plan_option_spellings_head()
{
    atf_set descr 'Every way config(8) accepts the option is refused'
}
plan_option_spellings_body()
{
    setup
    configuration S1 'ident S1' 'options FOO,DQ_TEST_OPEN'
    configuration S2 'ident S2' 'options DQ_TEST_OPEN=1'
    configuration S3 'ident S3' 'options FOO, DQ_TEST_OPEN, BAR'
    configuration S4 'ident S4' 'options FOO' '	DQ_TEST_OPEN'
    configuration S5 'ident S5' 'options DQ_TEST_OPEN # for the tests'
    configuration S6 'ident S6' 'options DQ_TEST_OPEN' 'nooptions DQ_TEST_OPEN'
    configuration S7 'ident S7' 'include S1'
    configuration S8 'ident S8' 'include "S7"'
    configuration S9 'ident S9' "include $PWD/conf/S2"
    for name in S1 S2 S3 S4 S5 S6 S7 S8 S9; do
        atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
            ./plan packages --kernel $name
    done
    # Not the option: a comment, a longer name, a shorter name.
    configuration N1 'ident N1' '#options DQ_TEST_OPEN' \
        'options FOO # DQ_TEST_OPEN' 'options DQ_TEST_OPENER' \
        'options XDQ_TEST_OPEN' 'options DQ_TEST'
    atf_check -s exit:0 -o match:'kernel-test-option-configuration=absent ' \
        -e empty ./plan packages --kernel N1
}

atf_test_case plan_fields
plan_fields_head()
{
    atf_set descr 'Plans report what was read and which check is requested'
}
plan_fields_body()
{
    setup
    configuration PLAIN 'ident PLAIN' 'options FOO'
    configuration OPTION 'ident OPTION' 'options DQ_TEST_OPEN'
    configuration MISSING 'ident MISSING' 'include "lg2-no-such-file"'
    configuration LOOP 'ident LOOP' 'include LOOP'
    # The mandatory-option fields follow (mandatory_option_test.sh).
    line='^publication: kernel-test-option-configuration=%s kernel-test-option-binary-check=%s kernel-mandatory-option-'

    atf_check -s exit:0 -o save:plan.out -e empty ./plan packages --kernel PLAIN
    atf_check -s exit:0 -o ignore \
        grep "$(printf "$line" absent requested)" plan.out
    atf_check -s exit:0 -o ignore grep '^system-packages:.*KERNCONF=PLAIN' plan.out
    # The signing and boot statements are untouched and separate.
    atf_check -s exit:0 -o ignore grep \
        '^security: verification-scope=system-bundles boot-verification=not-performed root-protection-verification=not-performed$' plan.out

    # What could not be read is said, never reported as absent.
    for name in MISSING LOOP; do
        atf_check -s exit:0 -o save:plan.out -e empty ./plan packages --kernel $name
        atf_check -s exit:0 -o ignore \
            grep "$(printf "$line" not-read requested)" plan.out
    done

    # Development actions may build a test kernel; no check is claimed.
    for action in kernel stage; do
        atf_check -s exit:0 -o save:plan.out -e empty ./plan $action --kernel OPTION
        atf_check -s exit:0 -o ignore \
            grep "$(printf "$line" present not-performed)" plan.out
    done
    atf_check -s exit:0 -o save:plan.out -e empty ./plan kernel --kernel PLAIN
    atf_check -s exit:0 -o ignore \
        grep "$(printf "$line" absent not-performed)" plan.out
    # No kernel is involved: nothing is read.
    atf_check -s exit:0 -o save:plan.out -e empty ./plan world --kernel OPTION
    atf_check -s exit:0 -o ignore \
        grep "$(printf "$line" not-performed not-performed)" plan.out

    atf_check -s exit:0 -o save:plan.out -e empty ./plan packages --kernel PLAIN \
        --format json
    atf_check -s exit:0 -o ignore grep \
        '"record":"request".*"kernel_test_option_configuration":"absent","kernel_test_option_binary_check":"requested"' plan.out
    atf_check -s exit:0 -o ignore grep \
        '"boot_verification":"not-performed","root_protection_verification":"not-performed"' plan.out
    atf_check -s exit:0 -o save:plan.out -e empty ./plan kernel --kernel OPTION \
        --format json
    atf_check -s exit:0 -o ignore grep \
        '"kernel_test_option_configuration":"present","kernel_test_option_binary_check":"not-performed"' plan.out
}

atf_test_case plan_steps
plan_steps_head()
{
    atf_set descr 'Snapshot, image and boot-stage plans check before they copy, build or stage'
}
plan_steps_body()
{
    setup
    mkdir repository root
    printf '{}' > repository/publication.json
    : > trust.pub
    printf '{}' > inventory.json
    printf '{}' > generated.json
    printf '{}' > receipt.json
    script=/usr/src/release/scripts/check-test-kernel.sh
    mandatory=/usr/src/release/scripts/check-mandatory-kernel.sh
    line='^publication: kernel-test-option-configuration=not-performed kernel-test-option-binary-check=requested kernel-mandatory-option-configuration=not-performed kernel-mandatory-option-binary-check=requested$'

    atf_check -s exit:0 -o save:plan.out -e empty "$tool" plan snapshot \
        --repository "$PWD/repository" --pkg-public-key "$PWD/trust.pub" \
        --package-tool /bin/sh --snapshot-abi FreeBSD:16:amd64 \
        --snapshot-osversion 1600027
    atf_check -s exit:0 -o ignore grep "$line" plan.out
    atf_check -s exit:0 -o inline:"kernel-test-option-check: sh $script -r $(realpath repository)\n" \
        sed -n 4p plan.out
    atf_check -s exit:0 -o inline:"kernel-mandatory-option-check: sh $mandatory -r $(realpath repository)\n" \
        sed -n 5p plan.out
    atf_check -s exit:0 -o match:'^snapshot: ' sed -n 6p plan.out
    atf_check -s exit:0 -o match:'^ *6$' wc -l < plan.out

    atf_check -s exit:0 -o save:plan.out -e empty "$tool" plan image \
        --root "$PWD/root" --inventory "$PWD/inventory.json" \
        --generated "$PWD/generated.json" \
        --construction-receipt "$PWD/receipt.json" --image-makefs /bin/sh \
        --image-mdconfig /bin/sh --image-mount /bin/sh --image-umount /bin/sh
    atf_check -s exit:0 -o ignore grep "$line" plan.out
    atf_check -s exit:0 -o inline:"kernel-test-option-check: sh $script -i $(realpath root)\n" \
        sed -n 4p plan.out
    atf_check -s exit:0 -o inline:"kernel-mandatory-option-check: sh $mandatory -i $(realpath root)\n" \
        sed -n 5p plan.out
    atf_check -s exit:0 -o match:'^image: ' sed -n 6p plan.out

    : > image.ufs
    : > boot.tar
    # Staging output is accepted only under /usr/obj; a plan creates nothing.
    staged=/usr/obj/usr/src/boot-stage-plan-lg2-$$
    atf_check -s exit:0 -o save:plan.out -e empty "$tool" plan boot-stage \
        --boot-image "$PWD/image.ufs" --boot-archive "$PWD/boot.tar" \
        --image-receipt "$PWD/receipt.json" --output "$staged"
    atf_check -s exit:0 -o ignore grep "$line" plan.out
    atf_check -s exit:0 -o inline:"kernel-test-option-check: sh $script -a $(realpath boot.tar)\n" \
        sed -n 4p plan.out
    atf_check -s exit:0 -o inline:"kernel-mandatory-option-check: sh $mandatory -a $(realpath boot.tar)\n" \
        sed -n 5p plan.out
    atf_check -s exit:0 -o match:'^boot-stage: ' sed -n 6p plan.out
    [ ! -e "$staged" ] || atf_fail 'a plan created its output'
    # boot-check writes nothing and runs no check.
    atf_check -s exit:0 -o save:plan.out -e empty "$tool" plan boot-check \
        --boot-image "$PWD/image.ufs" --boot-archive "$PWD/boot.tar" \
        --image-receipt "$PWD/receipt.json"
    atf_check -s exit:0 -o ignore grep \
        '^publication: kernel-test-option-configuration=not-performed kernel-test-option-binary-check=not-performed kernel-mandatory-option-configuration=not-performed kernel-mandatory-option-binary-check=not-performed$' \
        plan.out
    atf_check -s exit:0 -o match:'^boot-check: ' sed -n 4p plan.out
    [ ! -e /usr/obj/usr/src/repo ] || [ -d /usr/obj/usr/src/repo ] ||
        atf_fail 'unexpected repository object'
}

atf_test_case source_tree
source_tree_head()
{
    atf_set descr 'Configurations and includes are found in the source tree as config(8) finds them'
}
source_tree_body()
{
    setup
    # The only test configuration is amd64's.  Elsewhere this case has
    # nothing to read and says so; on amd64 a source tree without the
    # configuration is a failure, never a silent skip.
    [ "$(uname -p)" = amd64 ] ||
        atf_skip 'NOT CHECKED: no dq(4) test configuration exists for this machine'
    for file in sys/amd64/conf/GENERIC-TEST sys/amd64/conf/GENERIC \
        sys/conf/std.debug; do
        [ -f "/usr/src/$file" ] ||
            atf_fail "/usr/src/$file is missing: the source tree legs were not exercised"
    done
    # The test configuration itself, from sys/amd64/conf.
    atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
        env NO_KERNEL_DIR=1 ./plan packages --kernel GENERIC-TEST
    atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
        env NO_KERNEL_DIR=1 ./plan media --kernel GENERIC-TEST
    # GENERIC includes sys/conf/std.debug: every part is read.
    atf_check -s exit:0 -o match:'kernel-test-option-configuration=absent ' \
        -e empty env NO_KERNEL_DIR=1 ./plan packages --kernel GENERIC
    # An include that only sys/conf can satisfy is read there: the whole
    # configuration was read.  The control names a file that is nowhere,
    # which is reported as not read.
    configuration VIACONF 'ident VIACONF' 'include "std.debug"'
    atf_check -s exit:0 -o match:'kernel-test-option-configuration=absent ' \
        -e empty ./plan packages --kernel VIACONF
    [ ! -e /usr/src/sys/conf/std.lg2-nowhere ] &&
        [ ! -e /usr/src/sys/amd64/conf/std.lg2-nowhere ] ||
        atf_fail 'the control include exists'
    configuration NOWHERE 'ident NOWHERE' 'include "std.lg2-nowhere"'
    atf_check -s exit:0 -o match:'kernel-test-option-configuration=not-read ' \
        -e empty ./plan packages --kernel NOWHERE
    # The option reached through sys/conf and then sys/amd64/conf: a
    # private file includes std.debug (sys/conf only) and the test
    # configuration (sys/amd64/conf only).
    configuration VIABOTH 'ident VIABOTH' 'include "std.debug"' \
        'include GENERIC-TEST'
    atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
        ./plan packages --kernel VIABOTH
    # One that sys/amd64/conf satisfies.
    configuration VIAARCH 'ident VIAARCH' 'include GENERIC-TEST'
    atf_check -s exit:1 -o empty -e match:"$REFUSAL" \
        ./plan packages --kernel VIAARCH
    configuration VIAGENERIC 'ident VIAGENERIC' 'include GENERIC'
    atf_check -s exit:0 -o match:'kernel-test-option-configuration=absent ' \
        -e empty ./plan packages --kernel VIAGENERIC
}

atf_test_case publish_recipe
publish_recipe_head()
{
    atf_set descr 'The order of the publication recipe'
}
publish_recipe_body()
{
    setup
    private_tree
    atf_check -s exit:0 -o save:recipe.out -e ignore ./recipe -n publish-packages
    # Both inputs are checked for the test option before anything else,
    # and the destination parent is created only after every check.
    atf_check -s exit:0 -o inline:"sh $PWD/src/release/scripts/check-test-kernel.sh -r $PWD/base -r $PWD/hardware\n" \
        sed -n 1p recipe.out
    atf_check -s exit:0 -o match:'check-malloc-production.sh  *-r ' sed -n 2p recipe.out
    atf_check -s exit:0 -o inline:"sh $PWD/src/release/scripts/check-mandatory-kernel.sh -r $PWD/hardware\n" \
        sed -n 3p recipe.out
    atf_check -s exit:0 -o match:'^mkdir -p ' sed -n 4p recipe.out
    [ ! -e published ] || atf_fail 'a dry run created the destination'

    # The hardware repository is read after the hardware step, and by
    # nothing before it (hardware_check runs the recipe itself).
    for target in hardware-packages hardware-packages-check; do
        atf_check -s exit:0 -o save:recipe.out -e ignore ./recipe -n $target
        atf_check -s exit:0 -o match:'native-hardware\.py' sed -n 1p recipe.out
        atf_check -s exit:0 -o match:"check-test-kernel.sh -r $PWD/hardware;" \
            sed -n '$p' recipe.out
    done
    [ ! -e hardware ] || atf_fail 'a dry run created the hardware repository'

    # The object-tree check covers every configuration named.
    atf_check -s exit:0 -o save:recipe.out -e ignore ./recipe -n \
        KERNCONF='ONE TWO' OBJTOP=/lg2/objtop kernel-test-option-check
    printf 'sh %s -o /lg2/objtop/sys/%s\n' \
        "$PWD/src/release/scripts/check-test-kernel.sh" ONE \
        "$PWD/src/release/scripts/check-test-kernel.sh" TWO > expected
    atf_check -s exit:0 -o empty diff -u expected recipe.out
    # A check that names no kernel has read nothing: it fails.
    atf_check -s not-exit:0 -o not-match:'checked' \
        -e match:'KERNCONF names no kernel' \
        ./recipe KERNCONF= OBJTOP=/lg2/objtop kernel-test-option-check
    # system-packages runs it before packaging.
    atf_check -s exit:0 -o inline:'malloc-production-check\nkernel-test-option-check\nkernel-mandatory-option-check\npackages\nhardware-packages\npublish-packages\n' \
        sed -n '/^system-packages:/,$s/^	\${MAKE} -C \${.CURDIR} //p' \
        src/release/Makefile.hardware
}

atf_test_case hardware_check
hardware_check_head()
{
    atf_set descr 'hardware-packages-check on a fresh tree passes; a repository is always read'
    atf_set require.progs 'cc readelf'
}
hardware_check_body()
{
    setup
    private_tree
    HARDWARE_BUILDER=/usr/bin/true
    export HARDWARE_BUILDER

    # A fresh tree: the check-only target verifies inputs, creates no
    # repository and has none to read.  As before the test-option check.
    atf_check -s exit:0 -o not-match:'checked' -e empty \
        ./recipe hardware-packages-check
    [ ! -e hardware ] || atf_fail 'the check-only target created the repository'

    # A repository left by an earlier build is read.
    kernel_package hardware 5BSD-kernel-generic-nodebug-1.pkg plain
    atf_check -s exit:0 -o match:'1 kernel and boot files checked' -e empty \
        ./recipe hardware-packages-check
    kernel_package hardware 5BSD-kernel-generic-nodebug-1.pkg "$MARKER"
    atf_check -s not-exit:0 -o not-match:'checked' \
        -e match:'hardware/5BSD-kernel-generic-nodebug-1.pkg: boot/kernel/kernel was built with options DQ_TEST_OPEN, a test-kernel option' \
        ./recipe hardware-packages-check
    atf_check -s not-exit:0 -o not-match:'checked' -e match:'There is no' \
        ./recipe hardware-packages

    # One that is there but cannot be read as a repository is refused.
    rm -rf hardware
    : > hardware
    atf_check -s not-exit:0 -o not-match:'checked' -e not-empty \
        ./recipe hardware-packages-check
    rm hardware
    ln -s nowhere hardware
    atf_check -s not-exit:0 -o not-match:'checked' -e not-empty \
        ./recipe hardware-packages-check
    rm hardware

    # The build target must leave a repository: a missing one is refused,
    # and publication refuses it too (publish_refused).
    atf_check -s not-exit:0 -o not-match:'checked' \
        -e match:'repository does not exist' ./recipe hardware-packages
    [ ! -e hardware ] || atf_fail 'the check created the repository'

    # A hardware step that fails stops the recipe before the check.
    unset HARDWARE_BUILDER
    kernel_package hardware 5BSD-kernel-generic-nodebug-1.pkg plain
    atf_check -s not-exit:0 -o not-match:'checked' -e ignore \
        ./recipe hardware-packages-check
}

atf_test_case publish_refused
publish_refused_head()
{
    atf_set descr 'Publication refuses a test kernel in either input, or a hardware kernel without a mandatory option, and creates nothing'
    atf_set require.progs 'cc readelf'
}
publish_refused_body()
{
    setup
    private_tree

    # Control: clean inputs pass both checks, the destination parent is
    # created and only then does the (absent) publisher fail.
    clibs_package base
    kernel_package base 5BSD-kernel-generic-1.pkg plain
    kernel_package hardware 5BSD-kernel-generic-nodebug-1.pkg plain
    atf_check -s not-exit:0 -o match:'2 kernel and boot files checked' \
        -e not-match:'DQ_TEST_OPEN' ./recipe publish-packages
    [ -d published ] || atf_fail 'control: the destination parent was not created'
    [ ! -e published/complete ] || atf_fail 'control: something was published'
    rmdir published

    # A test kernel in the hardware repository: the copy that is published.
    kernel_package hardware 5BSD-kernel-generic-nodebug-1.pkg "$MARKER"
    atf_check -s not-exit:0 -o not-match:'checked' \
        -e match:'hardware/5BSD-kernel-generic-nodebug-1.pkg: boot/kernel/kernel was built with options DQ_TEST_OPEN, a test-kernel option' \
        ./recipe publish-packages
    [ ! -e published ] || atf_fail 'a refused publication created the destination'
    # No override: not the malloc one, not a guess at another.
    atf_check -s not-exit:0 -o not-match:'checked' -e match:'There is no' \
        ./recipe ALLOW_DEBUG_MALLOC=yes ALLOW_DQ_TEST_KERNEL=yes \
        ALLOW_TEST_KERNEL=yes publish-packages
    [ ! -e published ] || atf_fail 'a refused publication created the destination'

    # A test kernel in the base repository only.
    kernel_package hardware 5BSD-kernel-generic-nodebug-1.pkg plain
    kernel_package base 5BSD-kernel-generic-1.pkg 'has dq_testopen_bind in it'
    atf_check -s not-exit:0 -o not-match:'checked' \
        -e match:'base/5BSD-kernel-generic-1.pkg: boot/kernel/kernel was built' \
        ./recipe publish-packages
    [ ! -e published ] || atf_fail 'a refused publication created the destination'

    # A hardware kernel without a mandatory option, here RCTL.
    kernel_package base 5BSD-kernel-generic-1.pkg plain
    kernel_package hardware 5BSD-kernel-generic-nodebug-1.pkg plain \
        audit security_capability_mode security_capabilities racct
    atf_check -s not-exit:0 -o match:'2 kernel and boot files checked' \
        -e match:'hardware/5BSD-kernel-generic-nodebug-1.pkg: boot/kernel/kernel was built without options RCTL$' \
        ./recipe publish-packages
    [ ! -e published ] || atf_fail 'a refused publication created the destination'
    atf_check -s not-exit:0 -o not-match:'kernel\(s\) carry' \
        -e match:'built without options RCTL$' \
        env HARDWARE_BUILDER=/usr/bin/true ./recipe hardware-packages-check

    # A hardware repository that cannot be checked.
    kernel_package base 5BSD-kernel-generic-1.pkg plain
    rm -rf hardware
    atf_check -s not-exit:0 -o not-match:'checked' \
        -e match:'repository does not exist' ./recipe publish-packages
    [ ! -e published ] || atf_fail 'a refused publication created the destination'
    [ ! -e hardware ] || atf_fail 'the check created the repository'
}

atf_test_case ledger_options
ledger_options_head()
{
    atf_set descr 'build-bsd refuses every option of the source tree ledger, live or reserved'
}
ledger_options_body()
{
    setup
    # build-bsd reads /usr/src/sys/conf/test-options at run time; the check
    # script lists the same file.  Each option it lists is refused, so the
    # two readers cannot drift apart.
    [ -f /usr/src/sys/conf/test-options ] ||
        atf_fail '/usr/src/sys/conf/test-options is missing'
    atf_check -s exit:0 -o save:rows -e empty sh "$check" \
        -l /usr/src/sys/conf/test-options -L
    [ -s rows ] || atf_fail 'the ledger lists no option'
    for option in $(cut -d '|' -f 1 rows); do
        configuration "L$option" "ident L$option" "options	$option"
        atf_check -s exit:1 -o empty \
            -e match:"carries options $option, a test-kernel option" \
            ./plan packages --kernel "L$option"
        atf_check -s exit:1 -o empty \
            -e match:"carries options $option, a test-kernel option" \
            ./plan media --kernel "L$option"
        atf_check -s exit:0 -o match:'kernel-test-option-configuration=present ' \
            -e empty ./plan kernel --kernel "L$option"
    done
    # A name that is not a ledger row is not refused.
    configuration NOTROW 'ident NOTROW' 'options DQ_TEST_OPEN_NOT_A_ROW'
    atf_check -s exit:0 -o match:'kernel-test-option-configuration=absent ' \
        -e empty ./plan packages --kernel NOTROW
}

atf_test_case ledger_unreadable cleanup
ledger_unreadable_head()
{
    atf_set descr 'A test-option ledger the check script refuses refuses packages and media plans, others read nothing; an unreadable mandatory-option ledger refuses every kernel plan'
    atf_set require.user root
    atf_set require.kmods nullfs
    atf_set is.exclusive true
}
ledger_unreadable_body()
{
    setup
    configuration PLAIN 'ident PLAIN' 'options FOO'
    # Each crafted directory is mounted over /usr/src/sys/conf, where
    # build-bsd reads the ledger through the check script.  It carries the
    # real mandatory-option ledger, which build-bsd also reads there, except
    # in the last one, which carries the real test-option ledger alone.
    m='test kernel: not for publication'
    for kind in missing empty malformed symlink many no-mandatory; do
        rm -rf crafted
        mkdir crafted
        cp /usr/src/sys/conf/mandatory-options crafted/mandatory-options
        case $kind in
        missing) ;;
        no-mandatory)
            rm crafted/mandatory-options
            cp /usr/src/sys/conf/test-options crafted/test-options ;;
        empty) printf '# only a comment\n' > crafted/test-options ;;
        malformed) printf 'LG3|live|-|-|@(#)5BSD LG3 %s\n' "$m" > crafted/test-options ;;
        symlink)
            cp /usr/src/sys/conf/test-options real
            ln -s "$PWD/real" crafted/test-options ;;
        many)
            # No row limit: the last of 200 rows is seen.
            i=1
            while [ $i -le 200 ]; do
                printf 'LG3_%d|live|-|-|@(#)5BSD LG3_%d %s|-\n' $i $i "$m"
                i=$((i + 1))
            done > crafted/test-options ;;
        esac
        mount -t nullfs "$PWD/crafted" /usr/src/sys/conf ||
            atf_fail "cannot mount the crafted $kind ledger"
        if [ $kind = no-mandatory ]; then
            # Every plan that builds or carries a kernel is refused.
            for action in kernel stage packages media; do
                atf_check -s exit:1 -o empty \
                    -e match:'mandatory kernel option ledger /usr/src/sys/conf/mandatory-options cannot be read .*: no kernel is built or carried without it' \
                    ./plan $action --kernel PLAIN
            done
            atf_check -s exit:0 -o match:'kernel-mandatory-option-configuration=not-performed' \
                -e empty env NO_KERNEL_DIR=1 ./plan world
        elif [ $kind = many ]; then
            configuration LAST 'ident LAST' 'options LG3_200'
            atf_check -s exit:1 -o empty \
                -e match:'carries options LG3_200, a test-kernel option' \
                ./plan packages --kernel LAST
            atf_check -s exit:0 -o match:'kernel-test-option-configuration=absent ' \
                -e empty ./plan packages --kernel PLAIN
        else
            for action in packages media; do
                atf_check -s exit:1 -o empty \
                    -e match:"test-kernel option ledger /usr/src/sys/conf/test-options cannot be read .*: packages and media are refused" \
                    ./plan $action --kernel PLAIN
            done
            for action in kernel stage; do
                atf_check -s exit:0 -o match:'kernel-test-option-configuration=not-read ' \
                    -e empty ./plan $action --kernel PLAIN
            done
        fi
        umount /usr/src/sys/conf || atf_fail 'cannot unmount the crafted ledger'
    done
}
ledger_unreadable_cleanup()
{
    umount /usr/src/sys/conf 2>/dev/null || true
}

atf_test_case reconfigure_refused
reconfigure_refused_head()
{
    atf_set descr 'KERNFAST and NO_KERNELCONFIG: packages and media refuse, other actions read nothing'
}
reconfigure_refused_body()
{
    setup
    configuration PLAIN 'ident PLAIN' 'options FOO'
    for spelling in 'KERNFAST=' 'KERNFAST=yes' 'NO_KERNELCONFIG=yes' \
        '.if !defined(NO_KERNELCONFIG)' 'MAKEFLAGS+= -DKERNFAST'; do
        printf '%s\n' "$spelling" > make.conf
        atf_check -s exit:1 -o empty \
            -e match:'defines (KERNFAST|NO_KERNELCONFIG): the kernel would not be reconfigured' \
            ./plan packages --kernel PLAIN --make-conf "$PWD/make.conf"
        atf_check -s exit:1 -o empty -e match:'would not be reconfigured' \
            ./plan media --kernel PLAIN --make-conf "$PWD/make.conf"
        atf_check -s exit:0 -o match:'kernel-test-option-configuration=not-read ' \
            -e empty ./plan kernel --kernel PLAIN --make-conf "$PWD/make.conf"
    done
    # In a src configuration too.
    printf 'KERNFAST=yes\n' > src.conf
    atf_check -s exit:1 -o empty -e match:'would not be reconfigured' \
        ./plan packages --kernel PLAIN --src-conf "$PWD/src.conf"
    # Comments and longer names are not the variables.
    printf '# KERNFAST=yes\nXKERNFAST=yes\nNO_KERNELCONFIGURE=1\n' > make.conf
    atf_check -s exit:0 -o match:'kernel-test-option-configuration=absent ' \
        -e empty ./plan packages --kernel PLAIN --make-conf "$PWD/make.conf"
}

atf_test_case kernel_configuration_directory
kernel_configuration_directory_head()
{
    atf_set descr 'Every build step names KERNCONFDIR, so make.conf cannot choose another configuration'
}
kernel_configuration_directory_body()
{
    setup
    configuration PLAIN 'ident PLAIN' 'options FOO'
    printf 'KERNCONFDIR=/lg3/elsewhere\n' > make.conf
    atf_check -s exit:0 -o save:plan.out -e empty \
        ./plan packages --kernel PLAIN --make-conf "$PWD/make.conf"
    for name in buildworld buildkernel system-packages; do
        atf_check -s exit:0 -o ignore \
            grep "^$name:.* KERNCONFDIR=$PWD/conf " plan.out
    done
    atf_check -s exit:1 -o empty -e empty grep 'KERNCONFDIR=/lg3' plan.out
    # Without --kernel-dir, the tree's own directory, as Makefile.inc1
    # would choose.
    atf_check -s exit:0 -o save:plan.out -e empty env NO_KERNEL_DIR=1 \
        ./plan kernel --kernel GENERIC --make-conf "$PWD/make.conf"
    atf_check -s exit:0 -o ignore \
        grep "^buildkernel:.* KERNCONFDIR=/usr/src/sys/$(uname -m)/conf " plan.out
}

atf_test_case release_recipes
release_recipes_head()
{
    atf_set descr 'The release media recipes run the test-kernel check from the source tree'
    atf_set require.progs make
}
release_recipes_body()
{
    setup
    mkdir obj
    # A dry run of the kernel distribution: the check reads what was
    # distributed and every archive made, with the tree's script.
    atf_check -s exit:0 -o save:kernel.out -e ignore \
        env MAKEOBJDIRPREFIX="$PWD/obj" make -C /usr/src/release -n kernel.txz
    atf_check -s exit:0 -o ignore grep -E \
        '^sh /usr/src/release/scripts/check-test-kernel.sh -d .*/kernel$' kernel.out
    atf_check -s exit:0 -o ignore grep -F \
        'sh /usr/src/release/scripts/check-test-kernel.sh -a "$archive"' kernel.out
    # The media trees' check.
    atf_check -s exit:0 -o match:'^sh /usr/src/release/scripts/check-test-kernel.sh -d ' \
        -e ignore env MAKEOBJDIRPREFIX="$PWD/obj" \
        make -C /usr/src/release -V MEDIA_KERNEL_TEST_OPTION_CHECK
    # This file names the old script itself, so the tests directory is left out.
    atf_check -s exit:1 -o empty -e empty grep -r -l --exclude-dir=tests -e check-kernel-no-dq-test \
        /usr/src/release /usr/src/usr.sbin/bsd-build
}

atf_init_test_cases()
{
    atf_add_test_case plan_option_configuration
    atf_add_test_case plan_option_spellings
    atf_add_test_case plan_fields
    atf_add_test_case plan_steps
    atf_add_test_case source_tree
    atf_add_test_case publish_recipe
    atf_add_test_case hardware_check
    atf_add_test_case publish_refused
    atf_add_test_case ledger_options
    atf_add_test_case ledger_unreadable
    atf_add_test_case reconfigure_refused
    atf_add_test_case kernel_configuration_directory
    atf_add_test_case release_recipes
}
