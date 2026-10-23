# SPDX-License-Identifier: BSD-2-Clause
. $(atf_get_srcdir)/utils.subr
transaction_head_common() { atf_set require.user root; atf_set is.exclusive true; }
transaction_check() {
 pft_init
 vnet_mkjail transaction
 atf_check -s exit:0 -o inline:"PASS\n" -e empty jexec transaction \
     "$(atf_get_srcdir)/statusif_transaction" "$1"
}
atf_test_case statusif_set cleanup
statusif_set_head() { transaction_head_common; atf_set descr "Status interface assignment remains inactive until commit"; }
statusif_set_body() { transaction_check set; }
statusif_set_cleanup() { pft_cleanup; }
atf_test_case statusif_clear_commit cleanup
statusif_clear_commit_head() { transaction_head_common; atf_set descr "Status interface clearing remains inactive until commit"; }
statusif_clear_commit_body() { transaction_check clear_commit; }
statusif_clear_commit_cleanup() { pft_cleanup; }
atf_test_case statusif_clear_rollback cleanup
statusif_clear_rollback_head() { transaction_head_common; atf_set descr "Rolling back status interface clearing preserves active assignment"; }
statusif_clear_rollback_body() { transaction_check clear_rollback; }
statusif_clear_rollback_cleanup() { pft_cleanup; }
atf_init_test_cases() {
 atf_add_test_case statusif_set
 atf_add_test_case statusif_clear_commit
 atf_add_test_case statusif_clear_rollback
}
