# SPDX-License-Identifier: BSD-2-Clause
# Uses a real pkg database and files, entirely under the test's temporary root.
atf_test_case interrupted_package_operations
interrupted_package_operations_head()
{
    atf_set require.user root
    atf_set timeout 120
}
interrupted_package_operations_body()
{
    pkg=$(atf_config_get pkg_binary /usr/local/sbin/pkg)
    [ -x "$pkg" ] || atf_skip 'real pkg executable required'
    [ -x /usr/libexec/switchboard-pkg-reclaim ] || atf_skip 'install lifecycle helper in disposable guest first'
    ctl="$(atf_get_srcdir)/switchboardctl_test_bin"
    root="$(pwd)/target"
    mkdir "$root" stage packages
    echo payload > stage/retirement-fixture.txt
    echo retirement-fixture.txt > plist
    for version in 1 2; do
        cat > manifest <<MANIFEST
name: retirement-fixture
version: "$version"
origin: tests/retirement-fixture
comment: lifecycle qualification
desc: lifecycle qualification
maintainer: test@example.invalid
www: https://example.invalid
prefix: /
arch: '*'
scripts: {
 pre-install: '/usr/libexec/switchboard-pkg-reclaim begin-install pkg:retirement/fixture org.test.pkg/worker'
 post-install: 'test ! -e "\${PKG_ROOTDIR}/fail-install" || exit 42; /usr/libexec/switchboard-pkg-reclaim install pkg:retirement/fixture org.test.pkg/worker'
 pre-deinstall: '/usr/libexec/switchboard-pkg-reclaim prepare pkg:retirement/fixture org.test.pkg/worker'
 post-deinstall: 'test ! -e "\${PKG_ROOTDIR}/fail-remove" || exit 42; /usr/libexec/switchboard-pkg-reclaim retire pkg:retirement/fixture org.test.pkg/worker'
}
MANIFEST
        atf_check -o ignore -e ignore "$pkg" create -M manifest -p plist -r "$(pwd)/stage" -o packages
    done
    atf_check -o ignore -e ignore "$ctl" lifecycle run "$root" "$pkg" -r "$root" add "$(pwd)/packages/retirement-fixture-1.pkg"
    "$ctl" lifecycle status "$root" > initial
    old=$(awk '$1=="owner" {print $3}' initial)
    atf_check -o ignore -e ignore "$ctl" lifecycle run "$root" "$pkg" -r "$root" add -f "$(pwd)/packages/retirement-fixture-2.pkg"
    "$ctl" lifecycle status "$root" > upgraded
    atf_check awk -v old="$old" '$1=="owner" && $3==old && $4==1 {ok++} END {exit !(ok==1)}' upgraded
    touch "$root/fail-remove"
    atf_check -s exit:75 -o ignore -e match:'requires recovery' "$ctl" lifecycle run "$root" "$pkg" -r "$root" delete -y retirement-fixture
    atf_check test ! -e "$root/retirement-fixture.txt"
    "$ctl" lifecycle status "$root" > interrupted
    op=$(awk '$1=="operation" && $4==20 {print $5}' interrupted)
    atf_check "$ctl" lifecycle retire "$root" "$op" pkg:retirement/fixture org.test.pkg/worker
    rm "$root/fail-remove"
    touch "$root/fail-install"
    atf_check -s exit:75 -o ignore -e match:'requires recovery' "$ctl" lifecycle run "$root" "$pkg" -r "$root" add "$(pwd)/packages/retirement-fixture-1.pkg"
    atf_check test -f "$root/retirement-fixture.txt"
    "$ctl" lifecycle status "$root" > interrupted
    op=$(awk '$1=="operation" && $4==10 {print $5}' interrupted)
    atf_check "$ctl" lifecycle finish-install "$root" "$op" pkg:retirement/fixture org.test.pkg/worker
    "$ctl" lifecycle status "$root" > replacement
    atf_check awk -v old="$old" '$1=="owner" && $3!=old && $4==1 {ok++} END {exit !(ok==1)}' replacement
    atf_check -o ignore -e ignore "$ctl" lifecycle run "$root" "$pkg" -r "$root" delete -y retirement-fixture
}
# Exercise the shipped runtime scripts, including their account/database steps.
atf_test_case runtime_hooks_complete_every_principal
runtime_hooks_complete_every_principal_head()
{
    atf_set require.user root
    atf_set timeout 120
}
runtime_hooks_complete_every_principal_body()
{
    pkg=$(atf_config_get pkg_binary /usr/local/sbin/pkg)
    [ -x "$pkg" ] || atf_skip 'real pkg executable required'
    ctl="$(atf_get_srcdir)/switchboardctl_test_bin"
    runtime="$(atf_get_srcdir)/runtime.ucl"
    atf_check test -r "$runtime"
    root="$(pwd)/target"
    mkdir -p "$root/etc" stage packages
    cp /etc/master.passwd /etc/group /etc/services "$root/etc/"
    atf_check -o ignore -e ignore pwd_mkdb -p -d "$root/etc" "$root/etc/master.passwd"
    echo payload > stage/runtime-qualification.txt
    echo runtime-qualification.txt > plist
    for version in 1 2; do
        cat > manifest <<MANIFEST
name: runtime-authority-qa
version: "$version"
origin: tests/runtime-authority-qa
comment: runtime hooks qualification
desc: runtime hooks qualification
maintainer: test@example.invalid
www: https://example.invalid
prefix: /
arch: '*'
MANIFEST
        # Common package metadata is supplied above; retain all shipped scripts.
        sed '/^\.include/d' "$runtime" >> manifest
        atf_check -o ignore -e ignore "$pkg" create -M manifest -p plist -r "$(pwd)/stage" -o packages
    done
    labels='org.5bsd.user-session system.Filesystem/tzfsd system.Namespace/warden system.Sysctl/localsysctl system.SystemExtension/sysextd system.Waspnest/waspnest'
    atf_check -o ignore -e ignore "$ctl" lifecycle run "$root" "$pkg" -r "$root" add "$(pwd)/packages/runtime-authority-qa-1.pkg"
    for label in $labels; do
        "$ctl" lifecycle query "$root" "$label" >> initial
    done
    atf_check -o ignore -e ignore "$ctl" lifecycle run "$root" "$pkg" -r "$root" add -f "$(pwd)/packages/runtime-authority-qa-2.pkg"
    for label in $labels; do
        "$ctl" lifecycle query "$root" "$label" >> upgraded
    done
    atf_check cmp initial upgraded
    atf_check -o ignore -e ignore "$ctl" lifecycle run "$root" "$pkg" -r "$root" delete -y runtime-authority-qa
    while read -r label id rest; do
        atf_check -o match:"$id removed live-sources=0 staged-sources=0" "$ctl" lifecycle query "$root" "$label" "$id"
    done < initial
    "$ctl" lifecycle status "$root" > final
    atf_check awk '$1=="operation" && ($4==10 || $4==20) {exit 1}' final
}

# A package installed before the authority existed must keep its legacy key.
atf_test_case legacy_upgrade_adopts_resource_owner
legacy_upgrade_adopts_resource_owner_head()
{
    atf_set require.user root
    atf_set timeout 120
}
legacy_upgrade_adopts_resource_owner_body()
{
    pkg=$(atf_config_get pkg_binary /usr/local/sbin/pkg)
    [ -x "$pkg" ] || atf_skip 'real pkg executable required'
    ctl="$(atf_get_srcdir)/switchboardctl_test_bin"
    root="$(pwd)/target"
    mkdir "$root" stage packages
    echo legacy > stage/legacy-fixture.txt
    echo legacy-fixture.txt > plist
    cat > metadata <<'MANIFEST'
name: legacy-authority-fixture
origin: tests/legacy-authority-fixture
comment: lifecycle qualification
desc: lifecycle qualification
maintainer: test@example.invalid
www: https://example.invalid
prefix: /
arch: '*'
MANIFEST
    { echo 'version: "1"'; cat metadata; } > manifest
    atf_check -o ignore -e ignore "$pkg" create -M manifest -p plist -r "$(pwd)/stage" -o packages
    atf_check -o ignore -e ignore "$pkg" -r "$root" add "$(pwd)/packages/legacy-authority-fixture-1.pkg"
    atf_check test ! -e "$root/Capabilities/Config/switchboard/lifecycle"
    { echo 'version: "2"'; cat metadata; } > manifest
    cat >> manifest <<'MANIFEST'
scripts: {
 pre-install: '/usr/libexec/switchboard-pkg-reclaim begin-install pkg:tests/legacy-authority-fixture org.test.legacy/worker'
 post-install: '/usr/libexec/switchboard-pkg-reclaim install pkg:tests/legacy-authority-fixture org.test.legacy/worker'
}
MANIFEST
    echo updated > stage/legacy-fixture.txt
    atf_check -o ignore -e ignore "$pkg" create -M manifest -p plist -r "$(pwd)/stage" -o packages
    # pkg add -f is a replacement, not a repository upgrade: exercise the
    # real upgrade job so pkg supplies PKG_UPGRADE to the new package hooks.
    rm packages/legacy-authority-fixture-1.pkg
    mkdir repos
    printf 'legacy: { url: "file://%s/packages", enabled: yes }\n' "$(pwd)" > repos/legacy.conf
    atf_check -o ignore -e ignore "$pkg" repo packages
    atf_check -o ignore -e ignore "$pkg" -r "$root" -R "$(pwd)/repos" update -f
    atf_check -o ignore -e ignore "$ctl" lifecycle run "$root" "$pkg" -r "$root" -R "$(pwd)/repos" upgrade -y -r legacy
    atf_check -o inline:'updated\n' cat "$root/legacy-fixture.txt"
    atf_check -o match:' installed live-sources=1 staged-sources=0' "$ctl" lifecycle query "$root" org.test.legacy/worker
    "$ctl" lifecycle status "$root" > adopted
    atf_check awk '$1=="owner" && $2=="org.test.legacy/worker" && $4==1 && $5=="org.test.legacy/worker" {found++} END {exit !(found==1)}' adopted
    atf_check awk '$1=="operation" && ($4==10 || $4==20) {exit 1}' adopted
}

atf_init_test_cases()
{
    atf_add_test_case interrupted_package_operations
    atf_add_test_case runtime_hooks_complete_every_principal
    atf_add_test_case legacy_upgrade_adopts_resource_owner
}
