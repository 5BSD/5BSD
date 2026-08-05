#!/usr/libexec/atf-sh

atf_test_case manifest
manifest_body()
{
	src="@SRCTOP@/usr.sbin/rebootd"
	servicectl="@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin"
	bundle="${PWD}/Reboot.cap"

	test -x "${servicectl}" || atf_skip "servicectl test binary is required"
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	cp "@OBJTOP@/usr.sbin/rebootd/rebootd" "${bundle}/bin/rebootd"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S \
		    "@OBJTOP@/usr.sbin/rebootd/rebootd"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S \
		    "@OBJTOP@/usr.sbin/rebootd/rebootd"
	fi
	cp "${src}/capbundle/rebootd.ucl" "${bundle}/etc/rebootd.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}

atf_test_case security_contract
security_contract_body()
{
	source="@SRCTOP@/usr.sbin/rebootd/rebootd_main.c"
	manifest="@SRCTOP@/usr.sbin/rebootd/capbundle/rebootd.ucl"

	for token in service_provider_authorize_capabilities \
	    service_provider_enter_capability_mode \
	    SERVICE_PROTECT_NOFORK SERVICE_PROTECT_NOIPC \
	    SERVICE_PROTECT_NOFDRECV SERVICE_PROTECT_NOEXEC \
	    SERVICE_PROTECT_NOSOCK AU_DEFAUDITID
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" "${source}"
	done
	atf_check -s exit:0 -o empty awk '
	    /service_worker_protect/ { protect = NR }
	    /service_worker_drop_inherited_authority/ { drop = NR }
	    END { exit !(protect != 0 && drop != 0 && protect < drop) }
	' "${source}"
	for token in 'schema = "org.5bsd.serviced.service"' \
	    'schema_version = "1.0.0"' 'version = "1.0.0"' \
	    'user = "root"' 'components = \["filesystem"\]'
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" \
		    "${manifest}"
	done
}

atf_test_case observability_contract
observability_contract_body()
{
	provider="@SRCTOP@/usr.sbin/rebootd/rebootd_provider.d"
	source="@SRCTOP@/usr.sbin/rebootd/rebootd_main.c"
	for probe in session__start session__end request malformed schedule__create \
	    schedule__imminent schedule__cancel schedule__execute; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$provider"
	done
	for macro in REBOOTD_PROBE_SESSION_START REBOOTD_PROBE_SESSION_END \
	    REBOOTD_PROBE_REQUEST REBOOTD_PROBE_MALFORMED; do
		atf_check -s exit:0 -o ignore grep "$macro" "$source"
	done
}

atf_test_case singleton_coordinator_contract
singleton_coordinator_contract_body()
{
	source="@SRCTOP@/usr.sbin/rebootd/rebootd_main.c"
	for token in coordinator_add coordinator_tick coordinator_timeout \
	    REBOOTD_MAX_SESSIONS service_provider_quiesce_complete \
	    rebootd_store_load rebootd_store_save; do
		atf_check -s exit:0 -o ignore grep "${token}" "${source}"
	done
	atf_check -s exit:1 -o empty grep 'pdfork(' "${source}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case observability_contract
	atf_add_test_case singleton_coordinator_contract
}
