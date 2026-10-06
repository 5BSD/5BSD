# SPDX-License-Identifier: BSD-2-Clause
find_tool()
{
 tool="$(atf_get_srcdir)/policyctl_test_bin"
 [ -x "$tool" ] || tool=/usr/sbin/policyctl
 [ -x "$tool" ] || atf_skip "policyctl not installed"
}
fixture()
{
 mkdir -p App.cap/Units/client.unit/bin
 cat > App.cap/Bundle.ucl <<'POLICY'
schema="org.5bsd.capability-bundle";
bundle_id="org.test.app"; version="1.0.0"; sequence=1;
author="test"; publisher="org.test"; units=["client"];
POLICY
 printf '#!/bin/sh\nexit 0\n' > App.cap/Units/client.unit/bin/client
 chmod 755 App.cap/Units/client.unit/bin/client
}
atf_test_case roundtrip
roundtrip_head() { atf_set descr "Generated executable policy validates and exposes software attributes"; }
roundtrip_body()
{
 find_tool; fixture
 atf_check -s exit:0 -o save:App.cap/Units/client.unit/Unit.ucl -e empty "$tool" init client test.client
 atf_check -s exit:0 -o inline:'valid\n' -e empty "$tool" validate App.cap
 atf_check -s exit:0 -e empty -o inline:'{"units":[{"label":"org.test.app/client","exec":true,"attributes":["test.client"],"endpoints":[]}]}\n' "$tool" explain App.cap
}
atf_test_case empty_attributes
empty_attributes_body()
{
 find_tool; fixture
 atf_check -s exit:0 -o save:App.cap/Units/client.unit/Unit.ucl -e empty "$tool" init client
 atf_check -s exit:0 -o inline:'valid\n' -e empty "$tool" validate App.cap
 atf_check -s exit:0 -o match:'"attributes":\[\]' -e empty "$tool" explain App.cap
}
atf_test_case reject_input
reject_input_body()
{
 find_tool
 for program in ../client /bin/client 'bad"name' .hidden; do
  atf_check -s exit:2 -o empty -e match:'invalid program' "$tool" init "$program"
 done
 for attr in '*' 'bad"name' 'bad name'; do
  atf_check -s exit:2 -o empty -e match:'invalid attribute' "$tool" init client "$attr"
 done
 atf_check -s exit:2 -o empty -e match:'duplicate attribute' "$tool" init client test.client test.client
 atf_check -s exit:64 -o empty -e match:'usage:' "$tool" explain App.cap root
}
atf_test_case provider
provider_body()
{
 find_tool; fixture
 printf '%s\n' 'program="client"; activation {ipc=[{name="test.endpoint";requires=["test.client"];}];}' > App.cap/Units/client.unit/Unit.ucl
 atf_check -s exit:0 -o inline:'{"units":[{"label":"org.test.app/client","exec":false,"attributes":[],"endpoints":[{"name":"test.endpoint","requires":["test.client"]}]}]}\n' -e empty "$tool" explain App.cap
}
atf_test_case reject_invalid_bundle
reject_invalid_bundle_body()
{
 find_tool; fixture
 printf '%s\n' 'program="client"; activation {exec=true;boot=true;}' > App.cap/Units/client.unit/Unit.ucl
 atf_check -s exit:2 -o empty -e not-empty "$tool" validate App.cap
 printf '%s\n' 'principals { admin { uids=[0]; } }' > App.cap/Units/client.unit/Unit.ucl
 atf_check -s exit:2 -o empty -e not-empty "$tool" explain App.cap
}
atf_init_test_cases()
{
 atf_add_test_case roundtrip
 atf_add_test_case empty_attributes
 atf_add_test_case reject_input
 atf_add_test_case provider
 atf_add_test_case reject_invalid_bundle
}
