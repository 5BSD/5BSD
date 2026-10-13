# SPDX-License-Identifier: BSD-2-Clause
setup()
{
    script=$(atf_config_get pkgbase_script /usr/libexec/bsdinstall/pkgbase)
    [ -f "$script" ] || atf_fail 'pkgbase installer is missing'
    mkdir bin root repos
    export BSDINSTALL_CHROOT="$(pwd)/root"
    export BSDINSTALL_PKG_REPOS_DIR="$(pwd)/repos"
    export PKGBASE_FIXTURE="$(pwd)/catalogue"
    export PKGBASE_CALLS="$(pwd)/calls"
    export PATH="$(pwd)/bin:$PATH"
    export COMPONENTS=base
    unset BSDINSTALL_KERNEL
    cat > bin/pkg <<'MOCK'
#!/bin/sh
case " $* " in
*' rquery '*) cat "$PKGBASE_FIXTURE";;
*' install '*) printf '%s\n' "$*" >> "$PKGBASE_CALLS";;
esac
exit 0
MOCK
    chmod +x bin/pkg
    cat > catalogue <<'CATALOGUE'
pkg
5BSD-set-minimal
5BSD-set-base
5BSD-kernel-generic
5BSD-hw-drm
5BSD-hardware-abi-generic
CATALOGUE
}
atf_test_case explicit_kernel
explicit_kernel_body()
{
    setup
    printf '%s\n' 5BSD-kernel-custom-debug 5BSD-kernel-custom-debug-dbg >> catalogue
    export BSDINSTALL_KERNEL=CUSTOM_DEBUG COMPONENTS='base kernel-dbg'
    atf_check -s exit:0 -o empty -e empty /usr/libexec/flua "$script" --non-interactive
    atf_check -o match:5BSD-kernel-custom-debug -e empty cat calls
    atf_check -o match:5BSD-kernel-custom-debug-dbg -e empty cat calls
    atf_check -o match:5BSD-hw-drm -e empty cat calls
    atf_check -o match:5BSD-hardware-abi-generic -e empty cat calls
    atf_check -s exit:1 -o empty grep 5BSD-kernel-generic calls
}
atf_test_case unique_kernel
unique_kernel_body()
{
    setup
    sed 's/kernel-generic/kernel-custom/' catalogue > catalogue.new
    mv catalogue.new catalogue
    atf_check -s exit:0 -o empty -e empty /usr/libexec/flua "$script" --non-interactive
    atf_check -o match:5BSD-kernel-custom -e empty cat calls
    atf_check -o match:5BSD-hw-drm -e empty cat calls
}
atf_test_case reject_selection
reject_selection_body()
{
    setup
    export BSDINSTALL_KERNEL=MISSING
    atf_check -s not-exit:0 -o empty -e match:'exactly one selected kernel' /usr/libexec/flua "$script" --non-interactive
    [ ! -e calls ] || atf_fail 'installed with missing kernel'
    export BSDINSTALL_KERNEL='../GENERIC'
    atf_check -s not-exit:0 -o empty -e match:'invalid BSDINSTALL_KERNEL' /usr/libexec/flua "$script" --non-interactive
    [ ! -e calls ] || atf_fail 'installed with invalid kernel'
    unset BSDINSTALL_KERNEL
    echo 5BSD-kernel-alternate >> catalogue
    atf_check -s not-exit:0 -o empty -e match:'exactly one selected kernel' /usr/libexec/flua "$script" --non-interactive
    [ ! -e calls ] || atf_fail 'installed with ambiguous kernel'
}
atf_test_case jail_omits_hardware
jail_omits_hardware_body()
{
    setup
    sed '/kernel-/d' catalogue > catalogue.new
    mv catalogue.new catalogue
    printf '%s\n' 5BSD-set-minimal-jail >> catalogue
    atf_check -s exit:0 -o empty -e empty /usr/libexec/flua "$script" --non-interactive --jail
    atf_check -o match:5BSD-set-minimal-jail -e empty cat calls
    atf_check -s exit:1 -o empty grep -E '5BSD-(kernel-|hw-|hardware-abi-)' calls
}
atf_init_test_cases()
{
    atf_add_test_case explicit_kernel
    atf_add_test_case unique_kernel
    atf_add_test_case reject_selection
    atf_add_test_case jail_omits_hardware
}
