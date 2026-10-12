# SPDX-License-Identifier: BSD-2-Clause
setup()
{
    helper=$(atf_config_get repository_helper /usr/libexec/bsdinstall/repository.subr)
    [ -f "$helper" ] || atf_skip 'repository helper not installed'
    mkdir selected media
    printf '%s\n' '5BSD-base: { enabled: yes }' > selected/custom.conf
    printf '%s\n' '5BSD-base: { enabled: yes }' > media/5BSD-base-offline.conf
}
select_repository()
{
    /bin/sh -c '. "$1"; bsdinstall_repository "$2" "$3"' sh "$helper" "$1" "$2"
}
atf_test_case explicit_wins
explicit_wins_body()
{
    setup
    select_repository "$(pwd)/selected" "$(pwd)/media" > result || atf_fail 'selection failed'
    printf '%s\n' "$(pwd)/selected" > expected
    atf_check -s exit:0 -o empty diff -u expected result
    rm media/5BSD-base-offline.conf
    select_repository "$(pwd)/selected" "$(pwd)/media" > result || atf_fail 'explicit selection required media'
    atf_check -s exit:0 -o empty diff -u expected result
}
atf_test_case defaults
defaults_body()
{
    setup
    select_repository '' "$(pwd)/media" > result || atf_fail 'media selection failed'
    printf '%s\n' "$(pwd)/media" > expected
    atf_check -s exit:0 -o empty diff -u expected result
    rm media/5BSD-base-offline.conf
    select_repository '' "$(pwd)/media" > result || atf_fail 'network default failed'
    atf_check -s exit:0 test ! -s result
}
atf_test_case invalid_explicit_fails
invalid_explicit_fails_body()
{
    setup
    # Valid media must never hide an invalid explicitly selected repository.
    for directory in "$(pwd)/missing" relative; do
        if select_repository "$directory" "$(pwd)/media" > result 2> diagnostic; then
            atf_fail 'invalid explicit repository accepted'
        fi
        atf_check -s exit:0 test ! -s result
        atf_check -s exit:0 test -s diagnostic
    done
    rm selected/custom.conf
    if select_repository "$(pwd)/selected" "$(pwd)/media" > result 2> diagnostic; then
        atf_fail 'empty repository configuration accepted'
    fi
    atf_check -s exit:0 test ! -s result
}
atf_test_case media_trust_scope
media_trust_scope_body()
{
    setup
    mkdir media/keys media/repos
    echo fixture > media/keys/code.pub
    atf_check -s exit:0 -o inline:"$(pwd)/media/keys/code.pub\n" /bin/sh -c \
        '. "$1"; bsdinstall_media_code_key "$2" "$3"' sh "$helper" "$(pwd)/media/repos/" "$(pwd)/media"
    atf_check -s exit:0 -o empty /bin/sh -c \
        '. "$1"; bsdinstall_media_code_key "$2" "$3"' sh "$helper" "$(pwd)/selected" "$(pwd)/media"
    mv media/keys/code.pub public
    ln -s ../../public media/keys/code.pub
    atf_check -s exit:1 -o empty -e match:'code trust is missing or invalid' /bin/sh -c \
        '. "$1"; bsdinstall_media_code_key "$2" "$3"' sh "$helper" "$(pwd)/media/repos" "$(pwd)/media"
}
atf_init_test_cases()
{
    atf_add_test_case media_trust_scope
    atf_add_test_case explicit_wins
    atf_add_test_case defaults
    atf_add_test_case invalid_explicit_fails
}
