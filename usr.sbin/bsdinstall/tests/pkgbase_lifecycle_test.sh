# SPDX-License-Identifier: BSD-2-Clause
# Exercise the actual Lua installer against real, isolated pkg repositories.
setup_repo()
{
    if [ -n "${PKGBASE_INSTALLER:-}" ]; then
        script=$PKGBASE_INSTALLER
    elif [ -r '@SRCTOP@/usr.sbin/bsdinstall/scripts/pkgbase.in' ]; then
        script='@SRCTOP@/usr.sbin/bsdinstall/scripts/pkgbase.in'
    else
        script=/usr/libexec/bsdinstall/pkgbase
    fi
    root="$(pwd)/target root's"
    repos="$(pwd)/repo configs"
    mkdir -p "$root" "$repos" repository stage
    printf '5BSD-base: { url: "file://%s/repository", enabled: yes }\n' "$(pwd)" > "$repos/base.conf"
    printf 'installer-payload\n' > plist
    printf 'kernel-payload\n' > kernel-plist
    echo kernel > stage/kernel-payload
    cat > kernel-manifest <<'MANIFEST'
name: 5BSD-kernel-vbsd
version: "1"
origin: tests/kernel
comment: installer qualification
desc: isolated installer fixture
maintainer: test@example.invalid
www: https://example.invalid
prefix: /
arch: '*'
MANIFEST
    atf_check -o ignore -e ignore pkg create -M kernel-manifest -p kernel-plist -r "$(pwd)/stage" -o repository
}
publish()
{
    echo "$1" > stage/installer-payload
    printf 'version: "%s"\n' "$1" > manifest
    cat >> manifest <<'MANIFEST'
name: 5BSD-set-minimal
origin: tests/minimal
comment: installer qualification
desc: isolated installer fixture
maintainer: test@example.invalid
www: https://example.invalid
prefix: /
arch: '*'
scripts: {
 pre-install: '/usr/libexec/switchboard-pkg-reclaim begin-install pkg:tests/minimal org.test.installer/worker'
 post-install: 'test ! -e "${PKG_ROOTDIR}/fail-install" || exit 42; /usr/libexec/switchboard-pkg-reclaim install pkg:tests/minimal org.test.installer/worker'
}
MANIFEST
    atf_check -o ignore -e ignore pkg create -M manifest -p plist -r "$(pwd)/stage" -o repository
    atf_check -o ignore -e ignore pkg repo repository
}
install_target()
{
    env BSDINSTALL_CHROOT="$root" BSDINSTALL_PKG_REPOS_DIR="$repos" COMPONENTS= \
        /usr/libexec/flua "$script" --non-interactive
}
atf_test_case fresh_install_and_upgrade
fresh_install_and_upgrade_head()
{
    atf_set require.user root
    atf_set require.progs 'pkg /usr/libexec/flua /usr/sbin/switchboardctl /usr/libexec/switchboard-pkg-reclaim'
    atf_set timeout 120
}
fresh_install_and_upgrade_body()
{
    setup_repo
    publish 1
    install_target > install.log 2>&1 || atf_fail "installer failed: $(cat install.log)"
    atf_check -o inline:'1\n' cat "$root/installer-payload"
    switchboardctl lifecycle query "$root" org.test.installer/worker > initial
    atf_check -o match:' installed live-sources=1 staged-sources=0' cat initial
    rm repository/5BSD-set-minimal-1.pkg
    publish 2
    install_target > upgrade.log 2>&1 || atf_fail "upgrade failed: $(cat upgrade.log)"
    atf_check -o inline:'2\n' cat "$root/installer-payload"
    switchboardctl lifecycle query "$root" org.test.installer/worker > upgraded
    atf_check cmp initial upgraded
}
atf_test_case unfinished_hook_fails_installation
unfinished_hook_fails_installation_head()
{
    fresh_install_and_upgrade_head
}
unfinished_hook_fails_installation_body()
{
    setup_repo
    publish 1
    touch "$root/fail-install"
    if install_target > failed.log 2>&1; then atf_fail 'installer hid unfinished package hook'; fi
    atf_check -o ignore grep 'requires recovery' failed.log
    atf_check -o inline:'1\n' cat "$root/installer-payload"
    atf_check -o match:' installing ' switchboardctl lifecycle query "$root" org.test.installer/worker
    switchboardctl lifecycle status "$root" > ledger
    op=$(awk '$1=="operation" && $4==10 {print $5}' ledger)
    atf_check switchboardctl lifecycle finish-install "$root" "$op" pkg:tests/minimal org.test.installer/worker
    atf_check -o match:' installed ' switchboardctl lifecycle query "$root" org.test.installer/worker
}
atf_init_test_cases()
{
    atf_add_test_case fresh_install_and_upgrade
    atf_add_test_case unfinished_hook_fails_installation
}
