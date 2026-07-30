#!/usr/libexec/atf-sh

atf_test_case manifest
manifest_head()
{
	atf_set "descr" "netmapd is shipped as a verified core .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/netmapd"
	objdir="@OBJTOP@/usr.sbin/netmapd"
	servicectl="@OBJTOP@/usr.sbin/servicectl/servicectl"
	bundle="${PWD}/Netmapd.cap"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	cp "${objdir}/netmapd" "${bundle}/bin/netmapd"
	cp "${srcdir}/capbundle/netmapd.ucl" "${bundle}/etc/netmapd.ucl"
	chmod 0555 "${bundle}" "${bundle}/bin" "${bundle}/etc" \
	    "${bundle}/bin/netmapd"
	chmod 0444 "${bundle}/etc/netmapd.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
}
