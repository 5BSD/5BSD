#!/usr/libexec/atf-sh

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" "FileSystemCmp is a verified system .cap bundle"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/filesystemcmp"
	objdir="@OBJTOP@/usr.sbin/filesystemcmp"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/servicectl}"
	manifest="${srcdir}/capbundle/filesystemcmp.ucl"
	bundle="${PWD}/FileSystemCmp.cap"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	cp "${objdir}/filesystemcmp" "${bundle}/bin/filesystemcmp"
	cp "${manifest}" "${bundle}/etc/filesystemcmp.ucl"
	chmod 0555 "${bundle}" "${bundle}/bin" "${bundle}/etc" \
	    "${bundle}/bin/filesystemcmp"
	chmod 0444 "${bundle}/etc/filesystemcmp.ucl"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"

	chmod 0644 "${bundle}/etc/filesystemcmp.ucl"
	printf '%s\n' 'ambient_authority = true;' >> \
	    "${bundle}/etc/filesystemcmp.ucl"
	atf_check -s not-exit:0 -e match:'unknown key' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/FileSystemCmp.cap" 2>/dev/null || true
	rm -rf "${PWD}/FileSystemCmp.cap"
}

atf_test_case provider_security_contract
provider_security_contract_head()
{
	atf_set "descr" \
	    "FileSystemCmp workers are audited and propagation-hardened"
}
provider_security_contract_body()
{
	source="@SRCTOP@/usr.sbin/filesystemcmp/filesystemcmp.c"

	atf_check -s exit:0 -o match:'SERVICE_PROTECT_NOFORK' \
	    grep SERVICE_PROTECT_NOFORK "${source}"
	atf_check -s exit:0 -o match:'SERVICE_PROTECT_NOSOCK' \
	    grep SERVICE_PROTECT_NOSOCK "${source}"
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
	atf_check -s exit:0 -o match:'AUE_FILESYSTEMCMP_POLICY' \
	    grep AUE_FILESYSTEMCMP_POLICY "${source}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case provider_security_contract
}
