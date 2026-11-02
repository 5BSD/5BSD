# SPDX-License-Identifier: BSD-2-Clause
atf_test_case syntax
syntax_body()
{
    for name in main profile_chmod profile_coredump profile_dtmalloc profile_errno profile_hang profile_io profile_ip profile_jail profile_kill profile_lock profile_mib profile_namei profile_nanosleep profile_open profile_priv profile_proc profile_rw profile_sched profile_sendrecv profile_slow profile_systop profile_tcp profile_udp profile_udplite profile_vop_create profile_vop_readdir profile_vop_rename profile_vop_symlink template; do
        atf_check -s exit:0 -o empty -e empty \
            "$(atf_config_get loader)" -- "$(atf_config_get shell)" \
            -n "$(atf_config_get "$name")"
    done
}
atf_init_test_cases()
{
    atf_add_test_case syntax
}
