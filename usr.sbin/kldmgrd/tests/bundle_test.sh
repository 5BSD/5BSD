#!/usr/libexec/atf-sh

atf_test_case manifest
manifest_body()
{
	src="@SRCTOP@/usr.sbin/kldmgrd"
	servicectl="@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin"
	bundle="${PWD}/Kldmgr.cap"

	test -x "${servicectl}" || atf_skip "servicectl test binary is required"
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	cp "@OBJTOP@/usr.sbin/kldmgrd/kldmgrd" \
	    "${bundle}/bin/kldmgrd"
	if [ "@MK_DTRACE@" = "yes" ]; then
		atf_check -s exit:0 -o match:'.SUNW_dof' readelf -S \
		    "@OBJTOP@/usr.sbin/kldmgrd/kldmgrd"
	else
		atf_check -s exit:0 -o not-match:'.SUNW_dof' readelf -S \
		    "@OBJTOP@/usr.sbin/kldmgrd/kldmgrd"
	fi
	cp "${src}/capbundle/kldmgrd.ucl" "${bundle}/etc/kldmgrd.ucl"
	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
}

atf_test_case security_contract
security_contract_body()
{
	source="@SRCTOP@/usr.sbin/kldmgrd/kldmgrd_main.c"
	manifest="@SRCTOP@/usr.sbin/kldmgrd/capbundle/kldmgrd.ucl"

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
	    'user = "root"'
	do
		atf_check -s exit:0 -o match:"${token}" grep "${token}" \
		    "${manifest}"
	done
}

atf_test_case observability_contract
observability_contract_body()
{
	provider="@SRCTOP@/usr.sbin/kldmgrd/kldmgrd_provider.d"
	source="@SRCTOP@/usr.sbin/kldmgrd/kldmgrd_main.c"
	for probe in session__start session__end request malformed; do
		atf_check -s exit:0 -o ignore grep "probe ${probe}" "$provider"
	done
	for macro in KLDMGRD_PROBE_SESSION_START KLDMGRD_PROBE_SESSION_END \
	    KLDMGRD_PROBE_REQUEST KLDMGRD_PROBE_MALFORMED; do
		atf_check -s exit:0 -o ignore grep "$macro" "$source"
	done
}

atf_test_case bounded_worker_lifecycle
bounded_worker_lifecycle_body()
{
	source="@SRCTOP@/usr.sbin/kldmgrd/kldmgrd_main.c"
	for token in KLDMGRD_MAX_WORKERS EVFILT_PROCDESC NOTE_EXIT \
	    service_provider_quiescing service_provider_quiesce_complete \
	    pdkill pdwait; do
		atf_check -s exit:0 -o ignore grep "${token}" "${source}"
	done
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case security_contract
	atf_add_test_case observability_contract
	atf_add_test_case bounded_worker_lifecycle
}
