#!/usr/libexec/atf-sh

atf_test_case examples_verify cleanup
examples_verify_head()
{
	atf_set "descr" \
	    "Every installed Cmp scope example is a complete valid .cap manifest"
}
examples_verify_body()
{
	examples="@SRCTOP@/usr.sbin/serviced/examples"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/servicectl}"
	work="${PWD}/component-examples-work.$$"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	mkdir -p "${work}"
	providers="${work}/providers.cap"
	mkdir -p "${providers}/bin" "${providers}/etc"
	for kind in filesystem network; do
		printf '#!/bin/sh\nexit 0\n' > "${providers}/bin/${kind}cmp"
		chmod 0555 "${providers}/bin/${kind}cmp"
		cat > "${providers}/etc/${kind}cmp.ucl" <<EOF
bundle_id = "org.test.example-providers";
version = "1.0.0";
author = "test";
program = "${kind}cmp";
provides = ["org.test.${kind}cmp"];
implements = [{
    interface = "org.5bsd.cmp.${kind}";
    version = "1.0.0";
    lifetimes = ["process", "job", "jail", "system"];
    sharing = ["exclusive", "shared"];
}];
EOF
	done
	for scope in private jail service system; do
		bundle="${work}/${scope}.cap"
		manifest="${examples}/cmp-${scope}.ucl"
		program=$(sed -n 's/^[[:space:]]*program[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
		    "${manifest}")
		test -n "${program}" ||
		    atf_fail "${manifest} does not declare a program"
		mkdir -p "${bundle}/bin" "${bundle}/etc"
		printf '#!/bin/sh\nexit 0\n' > "${bundle}/bin/${program}"
		chmod 0555 "${bundle}/bin/${program}"
		cp "${manifest}" "${bundle}/etc/${program}.ucl"
		atf_check -s exit:0 -o match:'Verification: PASSED' \
		    "${servicectl}" verify "${providers}" "${bundle}"
	done
	atf_check -s exit:0 -o save:private-effective.out \
	    "${servicectl}" verify --effective "${providers}" \
	    "${work}/private.cap"
	atf_check -s exit:0 \
	    -o match:'lifetime=process sharing=exclusive required=yes' \
	    grep 'component: filesystem' private-effective.out
	atf_check -s exit:0 -o match:'user: capability' \
	    grep 'user:' private-effective.out
	atf_check -s exit:0 -o match:'group: capability' \
	    grep 'group:' private-effective.out
}
examples_verify_cleanup()
{
	rm -rf "${PWD}"/component-examples-work.*
	rm -f private-effective.out
}

atf_test_case pkgbase_default_identity
pkgbase_default_identity_head()
{
	atf_set "descr" \
	    "pkgbase owns the non-login capability identity and serviced only validates it"
}
pkgbase_default_identity_body()
{
	src="@SRCTOP@"

	passwd_line=$(awk -F: '$1 == "capability" { print; n++ }
	    END { if (n != 1) exit 1 }' "${src}/etc/master.passwd") ||
	    atf_fail "capability must occur exactly once in master.passwd"
	group_line=$(awk -F: '$1 == "capability" { print; n++ }
	    END { if (n != 1) exit 1 }' "${src}/etc/group") ||
	    atf_fail "capability must occur exactly once in group"

	uid=$(printf '%s\n' "${passwd_line}" | awk -F: '{ print $3 }')
	passwd_gid=$(printf '%s\n' "${passwd_line}" | awk -F: '{ print $4 }')
	group_gid=$(printf '%s\n' "${group_line}" | awk -F: '{ print $3 }')
	home=$(printf '%s\n' "${passwd_line}" | awk -F: '{ print $9 }')
	shell=$(printf '%s\n' "${passwd_line}" | awk -F: '{ print $10 }')
	test "${uid}" -gt 0 || atf_fail "capability UID must be non-root"
	test "${passwd_gid}" = "${group_gid}" ||
	    atf_fail "capability primary group does not match"
	test "${home}" = /nonexistent ||
	    atf_fail "capability home must be /nonexistent"
	test "${shell}" = /usr/sbin/nologin ||
	    atf_fail "capability shell must be nologin"

	atf_check -s exit:0 -o match:'SERVICED_DEFAULT_USER.*"capability"' \
	    grep SERVICED_DEFAULT_USER \
	    "${src}/lib/libcapbundle/serviced_manifest.h"
	atf_check -s exit:0 -o match:'SERVICED_DEFAULT_GROUP.*"capability"' \
	    grep SERVICED_DEFAULT_GROUP \
	    "${src}/lib/libcapbundle/serviced_manifest.h"
	atf_check -s exit:1 -o empty -e empty \
	    grep -E '(/usr/sbin/)?pw[[:space:]]+(useradd|groupadd)' \
	    "${src}/usr.sbin/serviced/serviced.c"
	atf_check -s exit:0 -o match:'never edits passwd or group' \
	    grep 'never edits passwd or group' \
	    "${src}/usr.sbin/serviced/serviced.c"
}

atf_test_case pkgbase_component_metadata
pkgbase_component_metadata_head()
{
	atf_set "descr" \
	    "Component libraries, providers, bundles, and tests have separate pkgbase identities"
}
pkgbase_component_metadata_body()
{
	src="@SRCTOP@"

	for package in filesystemcmp filesystemcmp-tests networkcmp \
	    networkcmp-tests \
	    libfilesystemcmp libfilesystemcmp-tests \
	    libnetworkcmp libnetworkcmp-tests \
	    libshmring libshmring-tests netmapd netmapd-tests
	do
		file="${src}/release/packages/ucl/${package}-all.ucl"
		test -s "${file}" ||
		    atf_fail "missing pkgbase metadata for ${package}"
	done
	for package in filesystemcmp-tests networkcmp-tests \
	    libfilesystemcmp-tests libnetworkcmp-tests libshmring-tests \
	    netmapd-tests
	do
		atf_check -s exit:0 -o match:'set = "tests"' \
		    grep 'set = ' \
		    "${src}/release/packages/ucl/${package}-all.ucl"
	done

	atf_check -s exit:0 -o match:'PACKAGE=.*filesystemcmp' \
	    grep '^PACKAGE' "${src}/usr.sbin/filesystemcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=.*netmapd' \
	    grep '^PACKAGE' "${src}/usr.sbin/netmapd/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=.*networkcmp' \
	    grep '^PACKAGE' "${src}/usr.sbin/networkcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libnetworkcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libfilesystemcmp/Makefile"

	atf_check -s exit:0 -o match:'CAP_BINPACKAGE=.*filesystemcmp' \
	    grep 'CAP_BINPACKAGE' "${src}/usr.sbin/filesystemcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_ETCPACKAGE=.*filesystemcmp' \
	    grep 'CAP_ETCPACKAGE' "${src}/usr.sbin/filesystemcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_BINPACKAGE=.*netmapd' \
	    grep 'CAP_BINPACKAGE' "${src}/usr.sbin/netmapd/Makefile"
	atf_check -s exit:0 -o match:'CAP_ETCPACKAGE=.*netmapd' \
	    grep 'CAP_ETCPACKAGE' "${src}/usr.sbin/netmapd/Makefile"
	atf_check -s exit:0 -o match:'CAP_BINPACKAGE=.*networkcmp' \
	    grep 'CAP_BINPACKAGE' "${src}/usr.sbin/networkcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_ETCPACKAGE=.*networkcmp' \
	    grep 'CAP_ETCPACKAGE' "${src}/usr.sbin/networkcmp/Makefile"

	for event in AUE_SERVICED_COMPONENT AUE_NETMAPD_BEARER \
	    AUE_NETWORKCMP_POLICY AUE_FILESYSTEMCMP_POLICY
	do
		atf_check -s exit:0 -o match:"${event}" \
		    grep "${event}" "${src}/sys/bsm/audit_kevents.h"
		atf_check -s exit:0 -o match:"${event}" \
		    grep "${event}" "${src}/contrib/openbsm/etc/audit_event"
	done
	atf_check -s exit:0 -o match:'AUE_NETMAPD_BEARER' \
	    grep AUE_NETMAPD_BEARER "${src}/usr.sbin/netmapd/netmapd.c"
	atf_check -s exit:0 -o match:'AUE_FILESYSTEMCMP_POLICY' \
	    grep AUE_FILESYSTEMCMP_POLICY \
	    "${src}/usr.sbin/filesystemcmp/filesystemcmp.c"
	atf_check -s exit:0 -o match:'AUE_NETWORKCMP_POLICY' \
	    grep AUE_NETWORKCMP_POLICY \
	    "${src}/usr.sbin/networkcmp/networkcmp.c"
	atf_check -s exit:0 -o match:'probe bootstrap__create' \
	    grep 'probe bootstrap__create' \
	    "${src}/usr.sbin/serviced/serviced_provider.d"
	atf_check -s exit:0 -o match:'phase=bootstrap' \
	    grep 'phase=bootstrap' "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:0 -o match:'probe svc__capmode' \
	    grep 'probe svc__capmode' \
	    "${src}/usr.sbin/serviced/serviced_provider.d"
	atf_check -s exit:0 -o match:'NOTE_EXIT.*NOTE_EXEC.*NOTE_CAPMODE' \
	    grep 'NOTE_EXIT.*NOTE_EXEC.*NOTE_CAPMODE' \
	    "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:0 -o match:'CAP_PDKILL.*CAP_PDGETPID.*CAP_EVENT' \
	    grep 'CAP_PDKILL.*CAP_PDGETPID.*CAP_EVENT' \
	    "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:0 -o match:'envfd_create' \
	    grep 'envfd_create' "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:0 -o match:'phase=capmode-ready' \
	    grep 'phase=capmode-ready' \
	    "${src}/usr.sbin/serviced/supervisor.c"
	for provider in \
	    "${src}/usr.sbin/serviced/serviced_provider.d" \
	    "${src}/usr.sbin/networkcmp/networkcmp_provider.d" \
	    "${src}/usr.sbin/netmapd/netmapd_provider.d" \
	    "${src}/lib/libnetworkcmp/networkcmp_provider.d" \
	    "${src}/lib/libfilesystemcmp/filesystemcmp_provider.d" \
	    "${src}/lib/libshmring/shmring_provider.d"
	do
		test -s "${provider}" ||
		    atf_fail "missing DTrace provider ${provider}"
	done
}

atf_test_case component_selector_contract
component_selector_contract_head()
{
	atf_set "descr" \
	    "Standard libraries use serviced-owned local-name selectors only"
}
component_selector_contract_body()
{
	src="@SRCTOP@"

	atf_check -s exit:0 -o match:'NETWORKCMP_ENV' \
	    grep NETWORKCMP_ENV \
	    "${src}/lib/libnetworkcmp/networkcmp.h"
	atf_check -s exit:0 -o match:'FILESYSTEMCMP_ENV' \
	    grep FILESYSTEMCMP_ENV \
	    "${src}/lib/libfilesystemcmp/filesystemcmp.h"
	atf_check -s exit:0 -o match:'SERVICE_NETWORKCMP_ENV' \
	    grep SERVICE_NETWORKCMP_ENV \
	    "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:0 -o match:'component_indices' \
	    grep component_indices "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:0 -o match:'NETWORKCMP' \
	    grep NETWORKCMP \
	    "${src}/lib/libcapbundle/libcapbundle_parse.c"
	atf_check -s exit:0 -o match:'service_component_fd' \
	    grep service_component_fd "${src}/lib/libnetworkcmp/networkcmp.c"
	atf_check -s exit:0 -o match:'service_component_fd' \
	    grep service_component_fd \
	    "${src}/lib/libfilesystemcmp/filesystemcmp.c"
}

atf_init_test_cases()
{
	atf_add_test_case examples_verify
	atf_add_test_case pkgbase_default_identity
	atf_add_test_case pkgbase_component_metadata
	atf_add_test_case component_selector_contract
}
