#!/usr/libexec/atf-sh

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" "NotifyCmp installs as a verified .cap provider"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/notifycmp"
	objdir="@OBJTOP@/usr.sbin/notifycmp"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	bundle="${PWD}/NotifyCmp.cap"

	test -x "${servicectl}" || atf_skip "test servicectl is required"
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	cp "${objdir}/notifycmp" "${bundle}/bin/notifycmp"
	cp "${srcdir}/capbundle/notifycmp.ucl" \
	    "${bundle}/etc/notifycmp.ucl"
	chmod 0555 "${bundle}" "${bundle}/bin" "${bundle}/etc" \
	    "${bundle}/bin/notifycmp"
	chmod 0444 "${bundle}/etc/notifycmp.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/NotifyCmp.cap" 2>/dev/null || true
	rm -rf "${PWD}/NotifyCmp.cap"
}

atf_test_case security_contract
security_contract_head()
{
	atf_set "descr" "NotifyCmp separates its system router from confined relays"
}
security_contract_body()
{
	source="@SRCTOP@/usr.sbin/notifycmp/notifycmp.c"
	for token in cap_enter SERVICE_PROTECT_NOFDRECV CAP_XFER_ONCE \
	    AUE_NOTIFYCMP_POLICY service_listener_accept EVFILT_TIMER
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
}

atf_test_case router_lifecycle_contract
router_lifecycle_contract_head()
{
	atf_set "descr" \
	    "NotifyCmp becomes ready only after its router and exits if that router dies"
}
router_lifecycle_contract_body()
{
	source="@SRCTOP@/usr.sbin/notifycmp/notifycmp.c"
	atf_check -s exit:0 -o match:'write.control' \
	    grep 'write(control' "${source}"
	atf_check -s exit:0 -o match:'router_error' \
	    grep router_error "${source}"
	atf_check -s exit:0 -o match:'pdwait' grep pdwait "${source}"
	atf_check -s exit:0 -o match:'restart = "on-failure"' \
	    grep restart \
	    "@SRCTOP@/usr.sbin/notifycmp/capbundle/notifycmp.ucl"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case router_lifecycle_contract
}
