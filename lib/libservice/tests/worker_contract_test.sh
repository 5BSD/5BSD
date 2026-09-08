#!/usr/libexec/atf-sh

atf_test_case privileged_pdfork_workers_drop_authority
privileged_pdfork_workers_drop_authority_head()
{
	atf_set "descr" \
	    "Every privileged provider worker explicitly drops pdfork-inherited authority"
}
privileged_pdfork_workers_drop_authority_body()
{
	local providers source srcroot

	srcroot="@SRCTOP@"
	test -d "${srcroot}/usr.sbin" ||
	    atf_skip "source tree (${srcroot}) required for contract checks"

	providers=$(find "${srcroot}/usr.sbin" -name '*.c' -type f -exec \
	    grep -l 'service_provider_enter_privileged' {} +)
	test -n "${providers}" ||
	    atf_fail "no privileged service providers found"

	for source in ${providers}; do
		atf_check -s exit:0 -o ignore \
		    grep -F 'service_worker_drop_inherited_authority();' "${source}"
	done
}

atf_init_test_cases()
{
	atf_add_test_case privileged_pdfork_workers_drop_authority
}
