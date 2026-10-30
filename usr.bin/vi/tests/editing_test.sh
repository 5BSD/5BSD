# SPDX-License-Identifier: BSD-2-Clause
prepare()
{
    export TMPDIR="$(pwd)"
    export EXINIT="set recdir=$(pwd)"
    unset NEXINIT VINIT
}
atf_test_case substitute
substitute_body()
{
    prepare
    printf 'alpha\nbeta\n' > input
    printf '%%s/alpha/ALPHA/\nwq\n' > commands
    printf 'ALPHA\nbeta\n' > expected
    atf_check -s exit:0 -o empty -e empty nvi -e -s input < commands
    atf_check -s exit:0 -o empty -e empty cmp input expected
}
atf_test_case append
append_body()
{
    prepare
    printf 'one\n' > input
    printf '$a\ntwo\nthree\n.\nwq\n' > commands
    printf 'one\ntwo\nthree\n' > expected
    atf_check -s exit:0 -o empty -e empty nvi -e -s input < commands
    atf_check -s exit:0 -o empty -e empty cmp input expected
}
atf_test_case undo
undo_body()
{
    prepare
    printf 'one\ntwo\n' > input
    printf '1d\nu\nwq\n' > commands
    printf 'one\ntwo\n' > expected
    atf_check -s exit:0 -o empty -e empty nvi -e -s input < commands
    atf_check -s exit:0 -o empty -e empty cmp input expected
}
atf_init_test_cases()
{
    atf_add_test_case substitute
    atf_add_test_case append
    atf_add_test_case undo
}
