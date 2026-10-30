# SPDX-License-Identifier: BSD-2-Clause
setup()
{
    tool=$(atf_config_get daemon /Capabilities/System/SystemExtension.cap/Units/bsdextension.unit/bin/BSDExtension)
    [ -x "$tool" ] || atf_fail "missing daemon input: $tool"
    library_path=$(atf_config_get library_path "")
}
atf_test_case missing_policy
missing_policy_head()
{
    atf_set descr 'Actual daemon refuses absent startup policy before acquiring provider resources'
    atf_set timeout 15
}
missing_policy_body()
{
    setup
    atf_check -s exit:1 -o empty -e match:'load extension policy .*missing.ucl:' env LD_LIBRARY_PATH="$library_path" "$tool" -c "$(pwd)/missing.ucl"
}
atf_test_case invalid_policy
invalid_policy_head()
{
    atf_set descr 'Actual daemon refuses malformed startup policy instead of reverting to broader grants'
    atf_set timeout 15
}
invalid_policy_body()
{
    setup
    printf '%s\n' 'allowed_extensions=[]; ignored=true;' > invalid.ucl
    atf_check -s exit:1 -o empty -e match:'load extension policy .*invalid.ucl:' env LD_LIBRARY_PATH="$library_path" "$tool" -c "$(pwd)/invalid.ucl"
}
atf_init_test_cases()
{
    atf_add_test_case missing_policy
    atf_add_test_case invalid_policy
}
