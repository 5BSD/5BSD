# SPDX-License-Identifier: BSD-2-Clause
. $(atf_get_srcdir)/utils.subr
import_head_common() { atf_set require.user root; atf_set is.exclusive true; }
import_check() {
 pft_init
 vnet_mkjail stateimport
 atf_check -s exit:0 -o match:PASS -e empty jexec stateimport $(atf_get_srcdir)/state_import_validation "$1"
}
atf_test_case valid cleanup
valid_head() { import_head_common; atf_set descr "State import validates valid before mutation"; }
valid_body() { import_check valid; }
valid_cleanup() { pft_cleanup; }
atf_test_case direction cleanup
direction_head() { import_head_common; atf_set descr "State import validates direction before mutation"; }
direction_body() { import_check direction; }
direction_cleanup() { pft_cleanup; }
atf_test_case src cleanup
src_head() { import_head_common; atf_set descr "State import validates src before mutation"; }
src_body() { import_check src; }
src_cleanup() { pft_cleanup; }
atf_test_case dst cleanup
dst_head() { import_head_common; atf_set descr "State import validates dst before mutation"; }
dst_body() { import_check dst; }
dst_cleanup() { pft_cleanup; }
atf_test_case name cleanup
name_head() { import_head_common; atf_set descr "State import validates name before mutation"; }
name_body() { import_check name; }
name_cleanup() { pft_cleanup; }
atf_test_case timeout cleanup
timeout_head() { import_head_common; atf_set descr "State import validates timeout before mutation"; }
timeout_body() { import_check timeout; }
timeout_cleanup() { pft_cleanup; }
atf_test_case creator cleanup
creator_head() { import_head_common; atf_set descr "State import validates creator before mutation"; }
creator_body() { import_check creator; }
creator_cleanup() { pft_cleanup; }
atf_init_test_cases() {
 atf_add_test_case valid
 atf_add_test_case direction
 atf_add_test_case src
 atf_add_test_case dst
 atf_add_test_case name
 atf_add_test_case timeout
 atf_add_test_case creator
}
