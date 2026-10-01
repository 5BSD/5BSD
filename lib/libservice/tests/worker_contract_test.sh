#!/usr/libexec/atf-sh

atf_test_case pdfork_workers_drop_authority
pdfork_workers_drop_authority_head()
{
	atf_set "descr" \
	    "Every provider that pdforks workers drops pdfork-inherited authority"
}
pdfork_workers_drop_authority_body()
{
	local providers source srcroot

	srcroot="@SRCTOP@"
	test -d "${srcroot}/usr.sbin" ||
	    atf_skip "source tree (${srcroot}) required for contract checks"

	# A provider that pdfork(2)s session workers must drop the authority the
	# child inherited, either explicitly or through
	# service_worker_enter_capability_mode(), which does it.
	providers=$(find "${srcroot}/usr.sbin" -path '*/tests' -prune -o \
	    -path "${srcroot}/usr.sbin/BSD*" -name '*.c' -type f -exec \
	    grep -lE '=[[:space:]]*pdfork\(' {} +)
	test -n "${providers}" ||
	    atf_fail "no pdfork-ing service providers found"

	for source in ${providers}; do
		if grep -qF 'service_worker_drop_inherited_authority();' \
		    "${source}" ||
		    grep -qF 'service_worker_enter_capability_mode(' "${source}"
		then
			continue
		fi
		atf_fail "${source} pdforks workers without dropping authority"
	done
}

atf_init_test_cases()
{
	atf_add_test_case pdfork_workers_drop_authority
}
