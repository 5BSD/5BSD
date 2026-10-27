# SPDX-License-Identifier: BSD-2-Clause
# These checks do not start listeners or authenticate users.
atf_test_case versions
versions_body()
{
    atf_check -s exit:0 -o empty -e match:'OpenSSH_' "$(atf_config_get sshd sshd)" -V
    atf_check -s exit:0 -o empty -e match:'OpenSSH_' "$(atf_config_get session /usr/libexec/sshd-session)" -V
    atf_check -s exit:0 -o empty -e match:'OpenSSH_' "$(atf_config_get auth /usr/libexec/sshd-auth)" -V
}

atf_test_case effective_config
effective_config_body()
{
    sshd=$(atf_config_get sshd sshd)
    keygen=$(atf_config_get keygen ssh-keygen)
    atf_check -s exit:0 -o empty -e empty "$keygen" -q -t ed25519 -N '' -f host_key
    atf_check -s exit:0 -o save:config.out -e empty "$sshd" -G -f /dev/null \
        -o "HostKey=$(pwd)/host_key" -o UsePAM=yes \
        -o PasswordAuthentication=no -o PermitRootLogin=no -o Port=22222
    pam=no password=no root=no port=no
    while IFS= read -r line; do
        case "$line" in
        'UsePAM yes') pam=yes ;;
        'PasswordAuthentication no') password=yes ;;
        'PermitRootLogin no') root=yes ;;
        'port 22222') port=yes ;;
        esac
    done < config.out
    [ "$pam:$password:$root:$port" = yes:yes:yes:yes ] || atf_fail 'explicit configuration was not preserved'
}

atf_test_case invalid_config
invalid_config_body()
{
    atf_check -s exit:1 -o empty -e match:'Bad configuration option' \
        "$(atf_config_get sshd sshd)" -G -f /dev/null -o InvalidTestOption=yes
}

atf_init_test_cases()
{
    atf_add_test_case versions
    atf_add_test_case effective_config
    atf_add_test_case invalid_config
}
