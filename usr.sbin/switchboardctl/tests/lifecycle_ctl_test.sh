# SPDX-License-Identifier: BSD-2-Clause

atf_test_case offline_retirement
offline_retirement_head() { atf_set require.user root; }
offline_retirement_body()
{
    ctl="$(atf_get_srcdir)/switchboardctl_test_bin"
    root="$(pwd)/target"
    one=11111111111111111111111111111111
    two=22222222222222222222222222222222
    mkdir "$root"
    atf_check "$ctl" lifecycle install "$root" pkg:fixture org.test.App/main
    "$ctl" lifecycle status "$root" > initial
    old=$(awk '/^owner/{print $3}' initial)
    atf_check -o match:"$old installed live-sources=1" "$ctl" lifecycle query "$root" org.test.App/main "$old"
    atf_check -o match:'unknown live-sources=0' "$ctl" lifecycle query "$root" org.test.Unknown/main
    atf_check -o match:'pkg:fixture' cat initial
    atf_check "$ctl" lifecycle prepare "$root" "$one" pkg:fixture org.test.App/main
    atf_check -s exit:75 -e match:'Device busy' "$ctl" lifecycle install "$root" pkg:fixture org.test.App/main
    atf_check "$ctl" lifecycle retire "$root" "$one" pkg:fixture org.test.App/main
    atf_check "$ctl" lifecycle install "$root" pkg:fixture org.test.App/main
    atf_check -o match:"$old removed live-sources=0" "$ctl" lifecycle query "$root" org.test.App/main "$old"
    atf_check "$ctl" lifecycle prepare "$root" "$two" pkg:fixture org.test.App/main
    "$ctl" lifecycle status "$root" > replacement
    atf_check awk -v old="$old" '
        $1=="owner" && $3==old && $4==4 {retired++}
        $1=="owner" && $3!=old && $4==2 {fresh++}
        END {exit !(retired==1 && fresh==1)}' replacement
    atf_check "$ctl" lifecycle prepare "$root" "$one" pkg:fixture org.test.App/main
    atf_check "$ctl" lifecycle retire "$root" "$one" pkg:fixture org.test.App/main
    "$ctl" lifecycle status "$root" > after_late_hook
    atf_check cmp replacement after_late_hook
    atf_check "$ctl" lifecycle cancel "$root" "$two" pkg:fixture org.test.App/main
    atf_check -s exit:75 -e match:'canceled' "$ctl" lifecycle retire "$root" "$two" pkg:fixture org.test.App/main
}

atf_test_case unsafe_root_and_atomic_failure
unsafe_root_and_atomic_failure_head() { atf_set require.user root; }
unsafe_root_and_atomic_failure_body()
{
    ctl="$(atf_get_srcdir)/switchboardctl_test_bin"
    root="$(pwd)/target"
    op=11111111111111111111111111111111
    mkdir "$root" host
    ln -s "$(pwd)/host" "$root/Capabilities"
    atf_check -s exit:77 -e match:'untrusted' "$ctl" lifecycle install "$root" pkg:fixture org.test.App/main
    atf_check test ! -e host/Config
    rm "$root/Capabilities"
    atf_check "$ctl" lifecycle install "$root" pkg:fixture org.test.App/main
    "$ctl" lifecycle status "$root" > before
    atf_check -s exit:75 -e match:'Stale' "$ctl" lifecycle prepare "$root" "$op" pkg:fixture org.test.App/main org.test.Missing/main
    "$ctl" lifecycle status "$root" > after
    atf_check cmp before after
    atf_check "$ctl" lifecycle prepare "$root" "$op" pkg:fixture org.test.App/main
    "$ctl" lifecycle status "$root" > before
    atf_check -s exit:75 -e match:'Invalid argument' "$ctl" lifecycle retire "$root" "$op" pkg:wrong org.test.App/main
    "$ctl" lifecycle status "$root" > after
    atf_check cmp before after
}

atf_test_case wrapper_binds_root_and_operation
wrapper_binds_root_and_operation_head() { atf_set require.user root; }
wrapper_binds_root_and_operation_body()
{
    ctl="$(atf_get_srcdir)/switchboardctl_test_bin"
    root="$(pwd)/target"
    mkdir "$root" other
    cat > child <<'CHILD'
#!/bin/sh
[ "$SWITCHBOARD_LIFECYCLE_ROOT" = "$1" ] || exit 1
[ "${#SWITCHBOARD_LIFECYCLE_OPERATION}" = 32 ] || exit 2
"$2" lifecycle begin-install "$1" "$SWITCHBOARD_LIFECYCLE_OPERATION" pkg:fixture org.test.App/main || exit 3
"$2" lifecycle finish-install "$1" "$SWITCHBOARD_LIFECYCLE_OPERATION" pkg:fixture org.test.App/main || exit 4
"$2" lifecycle install "$3" pkg:fixture org.test.App/main
CHILD
    atf_check -s exit:64 -e match:'root mismatch' "$ctl" lifecycle run "$root" /bin/sh ./child "$root" "$ctl" "$(pwd)/other"
    atf_check test ! -e other/Capabilities
    "$ctl" lifecycle status "$root" > state
    atf_check awk '$1=="owner" && $4==1 {active++} END {exit !(active==1)}' state
}

atf_test_case bounded_history
bounded_history_head() { atf_set require.user root; }
bounded_history_body()
{
    ctl="$(atf_get_srcdir)/switchboardctl_test_bin"
    root="$(pwd)/target"
    mkdir "$root"
    atf_check "$ctl" lifecycle install "$root" pkg:fixture org.test.App/main
    old=$("$ctl" lifecycle query "$root" org.test.App/main | awk '{print $2}')
    op=$("$ctl" lifecycle issue "$root") || atf_fail "issue failed"
    atf_check "$ctl" lifecycle prepare "$root" "$op" pkg:fixture org.test.App/main
    atf_check "$ctl" lifecycle retire "$root" "$op" pkg:fixture org.test.App/main
    atf_check "$ctl" lifecycle install "$root" pkg:fixture org.test.App/main
    atf_check -o match:'discarded [1-9]' "$ctl" lifecycle prune "$root" 1
    atf_check -o match:' unknown ' "$ctl" lifecycle query "$root" org.test.App/main "$old"
    "$ctl" lifecycle status "$root" > before
    atf_check -s exit:75 -e match:'Stale' "$ctl" lifecycle prepare "$root" "$op" pkg:fixture org.test.App/main
    "$ctl" lifecycle status "$root" > after
    atf_check cmp before after
    fresh=$("$ctl" lifecycle issue "$root") || atf_fail "issue failed"
    atf_check "$ctl" lifecycle prepare "$root" "$fresh" pkg:fixture org.test.App/main
    atf_check "$ctl" lifecycle retire "$root" "$fresh" pkg:fixture org.test.App/main
    atf_check -o match:' removed ' "$ctl" lifecycle query "$root" org.test.App/main
}

atf_test_case explicit_adoption_and_upgrade
explicit_adoption_and_upgrade_head() { atf_set require.user root; }
explicit_adoption_and_upgrade_body()
{
    ctl="$(atf_get_srcdir)/switchboardctl_test_bin"
    root="$(pwd)/target"
    label=org.test.Legacy/main
    mkdir "$root"
    atf_check "$ctl" lifecycle adopt "$root" pkg:legacy "$label"
    "$ctl" lifecycle status "$root" > before
    old=$(awk '$1=="owner" {print $3}' before)
    atf_check awk -v label="$label" '$1=="owner" && $5==label {ok++} END {exit !(ok==1)}' before
    atf_check awk '$1=="reference" && $7=="pkg:legacy" {ok++} END {exit !(ok==1)}' before
    op=$("$ctl" lifecycle issue "$root") || atf_fail "issue failed"
    atf_check "$ctl" lifecycle begin-adopt "$root" "$op" pkg:legacy "$label"
    atf_check -o match:' installing ' "$ctl" lifecycle query "$root" "$label"
    atf_check "$ctl" lifecycle finish-install "$root" "$op" pkg:legacy "$label"
    "$ctl" lifecycle status "$root" > after
    atf_check awk -v old="$old" -v label="$label" '$1=="owner" && $3==old && $4==1 && $5==label {ok++} END {exit !(ok==1)}' after
    atf_check awk '$1=="reference" && $4==1 && $7=="pkg:legacy" {ok++} END {exit !(ok==1)}' after
}

atf_init_test_cases()
{
    atf_add_test_case explicit_adoption_and_upgrade
    atf_add_test_case bounded_history
    atf_add_test_case offline_retirement
    atf_add_test_case unsafe_root_and_atomic_failure
    atf_add_test_case wrapper_binds_root_and_operation
}
