# SPDX-License-Identifier: BSD-2-Clause
atf_test_case static_only
static_only_head()
{
    atf_set descr 'Explicit policy validation uses native constraints without daemon effects'
}
static_only_body()
{
    tool=$(atf_config_get capsule /usr/sbin/capsule)
    [ -x "$tool" ] || atf_fail "selected capsule unavailable: $tool"
    libraries=$(atf_config_get capsule_library_path "")
    if [ -n "$libraries" ]; then
        export CAPSULE_TEST_PROGRAM="$tool"
        export CAPSULE_TEST_LIBRARY_PATH="$libraries"
        cat > selected-capsule <<'WRAPPER'
#!/bin/sh
exec env LD_LIBRARY_PATH="$CAPSULE_TEST_LIBRARY_PATH" "$CAPSULE_TEST_PROGRAM" "$@"
WRAPPER
        chmod 700 selected-capsule
        tool="$PWD/selected-capsule"
    fi
    cat > candidate.conf <<EOF
pidfile="$PWD/forbidden.pid";
control_socket="$PWD/forbidden.sock";
hostuuid="57061ee3-7587-4a12-9447-2ac2b0e947fe";
storage=[{recipient="test.Store/provider"; pool="testpool"; pool_guid="1";
 dataset="testpool/state"; dataset_guid="2"; devices=["/dev/nonexistent-test-device"];
 rights=[props_read,event,mount];}];
EOF
    chmod 600 candidate.conf
    atf_check -s exit:0 -o match:'syntax and static constraints only' -e empty "$tool" -n -f "$PWD/candidate.conf"
    atf_check -s exit:0 -o save:selection.json -e empty "$tool" -n -j -f "$PWD/candidate.conf"
    atf_check -s exit:0 -o match:'"format":2' grep '"scope":"capsule-effective-manager"' selection.json
    printf '%s\n' 'service_manager="/nonexistent/alternate-manager";' > selected.conf
    chmod 600 selected.conf
    atf_check -s exit:0 -o inline:'{"format":2,"scope":"capsule-effective-manager","service_manager":"/nonexistent/alternate-manager","boot_configuration":"/etc/capsule.conf","normal_boot_configuration":"/etc/capsule.conf"}\n' -e empty "$tool" -n -j -f "$PWD/selected.conf"
    printf '%s\n' 'service_manager="";' > selected.conf
    atf_check -s exit:0 -o inline:'{"format":2,"scope":"capsule-effective-manager","service_manager":"","boot_configuration":"/etc/capsule.conf","normal_boot_configuration":"/etc/capsule.conf"}\n' -e empty "$tool" -n -j -f "$PWD/selected.conf"
    atf_check -s not-exit:0 -o empty -e match:'usage:' "$tool" -j -f "$PWD/selected.conf"
    atf_check -s not-exit:0 -o empty -e match:'configuration error' "$tool" -n -j -f "$PWD/absent.conf"
    ln -s candidate.conf alias.conf
    atf_check -s not-exit:0 -o empty -e match:'configuration error' "$tool" -n -j -f "$PWD/alias.conf"
    mkdir policy-directory
    atf_check -s not-exit:0 -o empty -e match:'configuration error' "$tool" -n -j -f "$PWD/policy-directory"
    cp candidate.conf writable.conf
    chmod 666 writable.conf
    atf_check -s not-exit:0 -o empty -e match:'configuration error' "$tool" -n -j -f "$PWD/writable.conf"
    # Removed storage fields must not silently regain policy meaning.
    for obsolete in 'attachment="/state"' 'content=ordinary'; do
        sed "s|rights=|$obsolete; rights=|" candidate.conf > obsolete.conf
        chmod 600 obsolete.conf
        atf_check -s not-exit:0 -o empty -e match:'configuration error' "$tool" -n -f "$PWD/obsolete.conf"
    done
    [ ! -e forbidden.pid ] || atf_fail 'validation created pidfile'
    [ ! -e forbidden.sock ] || atf_fail 'validation created control socket'
    sed 's/props_read,event,mount/props_read,event,unrecognized/' candidate.conf > invalid.conf
    chmod 600 invalid.conf
    atf_check -s not-exit:0 -o empty -e match:'configuration error' "$tool" -n -f "$PWD/invalid.conf"
    atf_check -s not-exit:0 -o empty -e match:'usage:' "$tool" -n
    atf_check -s not-exit:0 -o empty -e match:'usage:' "$tool" -n -d -f "$PWD/candidate.conf"
    atf_check -s not-exit:0 -o empty -e match:'usage:' "$tool" -n -p "$PWD/forbidden.pid" -f "$PWD/candidate.conf"
}
atf_init_test_cases()
{
    atf_add_test_case static_only
}
