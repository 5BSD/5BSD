# SPDX-License-Identifier: BSD-2-Clause
# The raw format retains incremental import and duplicate/invalid-record handling.
# These tests require truthful I/O errors; they do not claim atomic restore.
. $(atf_get_srcdir)/utils.subr
statefile_head_common() { atf_set require.user root; atf_set is.exclusive true; }
statefile_init() { pft_init; vnet_mkjail statefile; }
atf_test_case empty cleanup
empty_head() { statefile_head_common; atf_set descr "Empty raw state files load without adding state"; }
empty_body() {
 statefile_init
 atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -S "$PWD/raw"
 [ -f raw ] && [ ! -s raw ] || atf_fail 'Empty snapshot was not created'
 atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -L "$PWD/raw"
 atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -ss
}
empty_cleanup() { pft_cleanup; }
atf_test_case truncated cleanup
truncated_head() { statefile_head_common; atf_set descr "Partial raw state records fail visibly"; }
truncated_body() {
 statefile_init
 printf x > raw
 atf_check -s exit:1 -o empty -e match:'truncated state record' jexec statefile pfctl -L "$PWD/raw"
 atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -ss
}
truncated_cleanup() { pft_cleanup; }
atf_test_case read_error cleanup
read_error_head() { statefile_head_common; atf_set descr "Raw state file read errors fail visibly"; }
read_error_body() {
 statefile_init
 atf_check -s exit:1 -o empty -e match:'read:' jexec statefile pfctl -L "$PWD"
 atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -ss
}
read_error_cleanup() { pft_cleanup; }
# pf_status.states counts allocations until deferred garbage collection,
# while -ss excludes unlinked states immediately.  Drain the cleared fixture
# before asserting the exact allocation count of the restored state.
statefile_wait_cleared() {
 for attempt in $(jot 30); do
  count=$(jexec statefile pfctl -si | awk '$1 == "current" && $2 == "entries" {print $3}')
  [ -n "$count" ] || atf_fail 'Missing allocated state count'
  echo "ALLOCATED_AFTER_CLEAR=$count"
  [ "$count" = 0 ] && return
  sleep 1
 done
 atf_fail 'Cleared state allocations did not drain'
}
statefile_roundtrip() {
 mode=$1
 pft_init
 ep=$(vnet_mkepair)
 vnet_mkjail statefile ${ep}b
 ifconfig ${ep}a 192.0.2.2/24 up
 jexec statefile ifconfig ${ep}b 192.0.2.1/24 up
 jexec statefile pfctl -e
 pft_set_rules statefile 'pass inet proto icmp keep state'
 atf_check -s exit:0 -o match:'1 packets received' -e empty jexec statefile ping -c 1 192.0.2.2
 atf_check -s exit:0 -o match:'current entries[[:space:]]+1[[:space:]]*$' jexec statefile pfctl -si
 atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -S "$PWD/raw"
 [ -s raw ] || atf_fail 'State export unexpectedly empty'
 jexec statefile pfctl -ss > before
 atf_check -s exit:0 -o ignore -e ignore jexec statefile pfctl -F states
 atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -ss
 statefile_wait_cleared
 if [ "$mode" = partial ]; then
  printf x >> raw
  atf_check -s exit:1 -o empty -e match:'truncated state record' jexec statefile pfctl -L "$PWD/raw"
 else
  atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -L "$PWD/raw"
  # Duplicate state IDs retain the existing successful no-op import contract.
  atf_check -s exit:0 -o empty -e empty jexec statefile pfctl -L "$PWD/raw"
 fi
 atf_check -s exit:0 -o match:'current entries[[:space:]]+1[[:space:]]*$' jexec statefile pfctl -si
 jexec statefile pfctl -ss > after
 atf_check -s exit:0 -o empty -e empty diff -u before after
}
atf_test_case roundtrip cleanup
roundtrip_head() { statefile_head_common; atf_set descr "Raw state roundtrip preserves tuples and duplicate IDs do not multiply states"; }
roundtrip_body() { statefile_roundtrip complete; }
roundtrip_cleanup() { pft_cleanup; }
atf_test_case partial cleanup
partial_head() { statefile_head_common; atf_set descr "Truncated tails report failure after prior complete raw records are imported"; }
partial_body() { statefile_roundtrip partial; }
partial_cleanup() { pft_cleanup; }

# Ordinary state display remains available even when raw persistence cannot
# represent the state's policy.  Refusal must not clobber an older snapshot.
statefile_rejected_export() {
 action=$1
 pft_init
 ep=$(vnet_mkepair)
 vnet_mkjail statefile ${ep}b
 ifconfig ${ep}a 192.0.2.2/24 up
 jexec statefile ifconfig ${ep}b 192.0.2.1/24 up
 jexec statefile pfctl -e
 pft_set_rules statefile 'set timeout { icmp.first 120, icmp.error 120 }' \
     "pass out quick inet proto icmp icmp-type echoreq $action" pass
 atf_check -s exit:0 -o match:'1 packets received' -e empty jexec statefile ping -c 1 192.0.2.2
 atf_check -s exit:0 -o match:'192.0.2.1' -e empty jexec statefile pfctl -ss
 printf 'previous snapshot\n' > previous
 cp previous raw
 atf_check -s exit:1 -o empty -e match:'raw state export cannot preserve' jexec statefile pfctl -S "$PWD/raw"
 atf_check -s exit:0 -o empty -e empty cmp previous raw
 atf_check -s exit:1 -o empty -e match:'raw state export cannot preserve' jexec statefile pfctl -S "$PWD/new.raw"
 [ ! -e new.raw ] || atf_fail 'Rejected export created its destination'
 atf_check -s exit:0 -o match:'192.0.2.1' -e empty jexec statefile pfctl -ss
}
atf_test_case delayed_export cleanup
delayed_export_head() { statefile_head_common; atf_set descr "Raw export refuses delayed states without losing an existing snapshot"; }
delayed_export_body() { statefile_rejected_export 'set delay 50'; }
delayed_export_cleanup() { pft_cleanup; }
atf_test_case tagged_export cleanup
tagged_export_head() { statefile_head_common; atf_set descr "Raw export refuses tagged states while ordinary state display works"; }
tagged_export_body() { statefile_rejected_export 'tag export_tag'; }
tagged_export_cleanup() { pft_cleanup; }

atf_init_test_cases() {
 atf_add_test_case delayed_export
 atf_add_test_case tagged_export
 atf_add_test_case empty
 atf_add_test_case truncated
 atf_add_test_case read_error
 atf_add_test_case roundtrip
 atf_add_test_case partial
}
