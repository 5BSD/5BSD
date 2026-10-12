# SPDX-License-Identifier: BSD-2-Clause
setup()
{
    openssl=$(atf_config_get openssl /usr/bin/openssl)
    module=$(atf_config_get fips_module /usr/lib/ossl-modules/fips.so)
    [ -f "$module" ] || atf_fail "FIPS provider missing: $module"
    mkdir modules
    cp "$module" modules/fips.so
    export OPENSSL_MODULES="$PWD/modules"
    export OPENSSL_CONF=/dev/null
    atf_check -s exit:0 -o ignore -e ignore "$openssl" fipsinstall \
        -pedantic -self_test_onload -module "$OPENSSL_MODULES/fips.so" \
        -out "$PWD/fipsmodule.cnf"
    profile=$(atf_config_get fips_profile /etc/ssl/openssl-fips.cnf)
    sed "s|/etc/ssl/fipsmodule.cnf|$PWD/fipsmodule.cnf|" "$profile" > strict.cnf
    export OPENSSL_CONF="$PWD/strict.cnf"
    printf abc > data
}
atf_test_case strict_algorithms
strict_algorithms_body()
{
    setup
    atf_check -s exit:0 -o match:'5BSD FIPS provider \(not validated\)' -e empty "$openssl" list -providers
    atf_check -s exit:0 -o match:'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' -e empty "$openssl" dgst -sha256 data
    atf_check -s not-exit:0 -o ignore -e match:'unsupported' "$openssl" dgst -md5 data
    # Even explicitly loading default must not silently bypass fips=yes.
    atf_check -s not-exit:0 -o ignore -e match:'unsupported' "$openssl" dgst -provider default -md5 data
    # The ordinary profile remains available and unaffected.
    atf_check -s exit:0 -o match:'900150983cd24fb0d6963f7d28e17f72' -e empty env OPENSSL_CONF=/dev/null "$openssl" dgst -md5 data
}
atf_test_case module_tamper
module_tamper_body()
{
    setup
    chmod u+w "$OPENSSL_MODULES/fips.so"
    printf tampered >> "$OPENSSL_MODULES/fips.so"
    atf_check -s not-exit:0 -o ignore -e ignore "$openssl" dgst -sha256 data
    atf_check -s not-exit:0 -o ignore -e ignore env OPENSSL_CONF=/dev/null "$openssl" fipsinstall -verify -module "$OPENSSL_MODULES/fips.so" -in fipsmodule.cnf
}
atf_test_case missing_configuration
missing_configuration_body()
{
    setup
    rm fipsmodule.cnf
    atf_check -s not-exit:0 -o ignore -e ignore "$openssl" dgst -sha256 data
}
atf_test_case missing_module
missing_module_body()
{
    setup
    rm "$OPENSSL_MODULES/fips.so"
    atf_check -s not-exit:0 -o ignore -e ignore "$openssl" dgst -sha256 data
}
atf_test_case self_test_failure
self_test_failure_body()
{
    setup
    atf_check -s not-exit:0 -o ignore -e match:'Fail' env OPENSSL_CONF=/dev/null "$openssl" fipsinstall -pedantic -self_test_onload -module "$OPENSSL_MODULES/fips.so" -out rejected.cnf -corrupt_type KAT_Digest
    [ ! -s rejected.cnf ] || atf_fail 'published configuration after failed self-test'
}
atf_test_case security_checks
security_checks_body()
{
    setup
    # Strict HMAC rejects a key below 112 bits even though HMAC itself is approved.
    atf_check -s not-exit:0 -o ignore -e ignore "$openssl" mac -digest SHA256 -macopt hexkey:01 -in data HMAC
    atf_check -s exit:0 -o not-empty -e empty "$openssl" mac -digest SHA256 -macopt hexkey:000102030405060708090a0b0c0d0e0f -in data HMAC
    atf_check -s exit:0 -o ignore -e ignore env OPENSSL_CONF=/dev/null "$openssl" fipsinstall -verify -module "$OPENSSL_MODULES/fips.so" -in fipsmodule.cnf
}
atf_test_case signing
signing_body()
{
    setup
    atf_check -s exit:0 -o ignore -e empty "$openssl" genpkey -algorithm ED25519 -out key
    atf_check -s exit:0 -o ignore -e empty "$openssl" pkey -in key -pubout -out public
    atf_check -s exit:0 -o ignore -e empty "$openssl" pkeyutl -sign -rawin -inkey key -in data -out signature
    atf_check -s exit:0 -o ignore -e empty "$openssl" pkeyutl -verify -rawin -pubin -inkey public -in data -sigfile signature
    printf changed >> data
    atf_check -s not-exit:0 -o ignore -e ignore "$openssl" pkeyutl -verify -rawin -pubin -inkey public -in data -sigfile signature
}
atf_init_test_cases()
{
    atf_add_test_case strict_algorithms
    atf_add_test_case module_tamper
    atf_add_test_case missing_configuration
    atf_add_test_case missing_module
    atf_add_test_case self_test_failure
    atf_add_test_case security_checks
    atf_add_test_case signing
}
