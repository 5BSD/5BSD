#!/usr/libexec/atf-sh

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" "Kernel NetworkCmp is a verified system .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/networkcmp"
	objdir="@OBJTOP@/usr.sbin/networkcmp"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	manifest="${srcdir}/capbundle/networkcmp.ucl"
	bundle="${PWD}/NetworkCmp.cap"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	cp "${objdir}/networkcmp" "${bundle}/bin/networkcmp"
	cp "${manifest}" "${bundle}/etc/networkcmp.ucl"
	chmod 0555 "${bundle}" "${bundle}/bin" "${bundle}/etc" \
	    "${bundle}/bin/networkcmp"
	chmod 0444 "${bundle}/etc/networkcmp.ucl"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
	atf_check -s exit:0 -o match:'org.5bsd.NetworkCmp' \
	    grep 'provides' "${manifest}"
	atf_check -s exit:1 -o empty -e empty \
	    grep 'interface' "${manifest}"
	atf_check -s exit:0 -o match:'version = "1.0.0"' \
	    grep 'version = "1.0.0"' "${manifest}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/NetworkCmp.cap" 2>/dev/null || true
	rm -rf "${PWD}/NetworkCmp.cap"
}

atf_test_case kernel_security_contract
kernel_security_contract_head()
{
	atf_set "descr" \
	    "Kernel worker uses an attenuated network broker in capability mode"
}
kernel_security_contract_body()
{
	source="@SRCTOP@/usr.sbin/networkcmp/networkcmp.c"

	atf_check -s exit:0 -o match:'NETWORKCMP_FEATURE_DNS' \
	    grep NETWORKCMP_FEATURE_DNS "${source}"
	atf_check -s exit:0 -o match:'cap_getaddrinfo' \
	    grep cap_getaddrinfo "${source}"
	atf_check -s exit:0 -o match:'CAPNET_NAME2ADDR' \
	    grep CAPNET_NAME2ADDR "${source}"
	atf_check -s exit:0 -o match:'CAPNET_CONNECT' \
	    grep CAPNET_CONNECT "${source}"
	atf_check -s exit:0 -o match:'CAPNET_BIND' \
	    grep CAPNET_BIND "${source}"
	atf_check -s exit:0 -o match:'cap_connect' \
	    grep cap_connect "${source}"
	atf_check -s exit:0 -o match:'cap_bind' \
	    grep cap_bind "${source}"
	atf_check -s exit:0 -o match:'socket' \
	    grep -F 'socket(' "${source}"
	atf_check -s exit:0 -o match:'CAP_XFER_NONE' \
	    grep CAP_XFER_NONE "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOFORK_ONCE' \
	    grep CAP_CLOFORK_ONCE "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOFORK_LOCKED' \
	    grep CAP_CLOFORK_LOCKED "${source}"
	atf_check -s exit:0 -o match:'CAP_CLOEXEC_LOCKED' \
	    grep CAP_CLOEXEC_LOCKED "${source}"
	atf_check -s exit:0 -o match:'cap_enter' \
	    grep cap_enter "${source}"
	atf_check -s exit:0 -o match:'AUE_NETWORKCMP_POLICY' \
	    grep AUE_NETWORKCMP_POLICY "${source}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case kernel_security_contract
}
