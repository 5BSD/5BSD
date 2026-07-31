#!/usr/libexec/atf-sh

atf_test_case examples_verify cleanup
examples_verify_head()
{
	atf_set "descr" \
	    "The installed local-component example is a complete valid manifest"
}
examples_verify_body()
{
	examples="@SRCTOP@/usr.sbin/serviced/examples"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	work="${PWD}/component-examples-work.$$"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	manifest="${examples}/local-components.ucl"
	bundle="${work}/local-components.cap"
	program=$(sed -n 's/^[[:space:]]*program[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
	    "${manifest}")
	mkdir -p "${bundle}/bin" "${bundle}/etc"
	printf '#!/bin/sh\nexit 0\n' > "${bundle}/bin/${program}"
	chmod 0555 "${bundle}/bin/${program}"
	cp "${manifest}" "${bundle}/etc/${program}.ucl"
	atf_check -s exit:0 -o save:effective.out \
	    "${servicectl}" verify "${bundle}"
	atf_check -s exit:0 -o match:'component: filesystem' \
	    grep 'component: filesystem' effective.out
	atf_check -s exit:0 -o match:'component: network' \
	    grep 'component: network' effective.out
	atf_check -s exit:0 -o match:'user: capability' \
	    grep 'user:' effective.out
	atf_check -s exit:0 -o match:'group: capability' \
	    grep 'group:' effective.out
}
examples_verify_cleanup()
{
	rm -rf "${PWD}"/component-examples-work.*
	rm -f effective.out
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

	for package in filesystemcmp filesystemcmp-tests logcmp logcmp-tests \
	    notifycmp notifycmp-tests \
	    tracecmp tracecmp-tests \
	    networkcmp \
	    networkcmp-tests \
	    libchannel libchannel-tests \
	    libservice libservice-tests \
	    libfilesystemcmp libfilesystemcmp-tests \
	    liblogcmp liblogcmp-tests \
	    libnotifycmp libnotifycmp-tests \
	    libtracecmp libtracecmp-tests \
	    libnetworkcmp libnetworkcmp-tests \
	    libshmring libshmring-tests
	do
		file="${src}/release/packages/ucl/${package}-all.ucl"
		test -s "${file}" ||
		    atf_fail "missing pkgbase metadata for ${package}"
	done
	for package in filesystemcmp-tests logcmp-tests tracecmp-tests \
	    notifycmp-tests \
	    networkcmp-tests \
	    libchannel-tests \
	    libservice-tests \
	    liblogcmp-tests \
	    libtracecmp-tests \
	    libnotifycmp-tests \
	    libfilesystemcmp-tests libnetworkcmp-tests libshmring-tests
	do
		atf_check -s exit:0 -o match:'set = "tests"' \
		    grep 'set = ' \
		    "${src}/release/packages/ucl/${package}-all.ucl"
	done

	atf_check -s exit:0 -o match:'PACKAGE=.*filesystemcmp' \
	    grep '^PACKAGE' "${src}/usr.sbin/filesystemcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=.*networkcmp' \
	    grep '^PACKAGE' "${src}/usr.sbin/networkcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=.*logcmp' \
	    grep '^PACKAGE' "${src}/usr.sbin/logcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=.*tracecmp' \
	    grep '^PACKAGE' "${src}/usr.sbin/tracecmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=.*notifycmp' \
	    grep '^PACKAGE' "${src}/usr.sbin/notifycmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libchannel/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libservice/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libnetworkcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libfilesystemcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/liblogcmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libtracecmp/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libnotifycmp/Makefile"
	for package in libchannel libshmring libfilesystemcmp libnetworkcmp \
	    liblogcmp libnotifycmp libtracecmp filesystemcmp networkcmp \
	    logcmp notifycmp tracecmp
	do
		atf_check -s exit:0 -o match:"WORLDPACKAGE=.*${package}" \
		    grep '^WORLDPACKAGE' \
		    "${src}/packages/${package}/Makefile"
		atf_check -s exit:0 -o match:"${package}" \
		    grep -E "^[[:space:]]*${package}[[:space:]]*\\\\" \
		    "${src}/packages/Makefile"
	done
	for package in libchannel libshmring libfilesystemcmp libnetworkcmp \
	    liblogcmp libnotifycmp libtracecmp filesystemcmp networkcmp \
	    logcmp notifycmp tracecmp
	do
		atf_check -s exit:0 \
		    -o match:"WORLDPACKAGE=.*${package}-tests" \
		    grep '^WORLDPACKAGE' \
		    "${src}/packages/${package}-tests/Makefile"
	done
	atf_check -s exit:0 -o match:'PKG_DEPS.libservice.*libchannel' \
	    grep 'PKG_DEPS.libservice.*libchannel' \
	    "${src}/packages/libservice/Makefile"
	atf_check -s exit:0 -o match:'PKG_DEPS.serviced.*libchannel' \
	    grep 'PKG_DEPS.serviced.*libchannel' \
	    "${src}/packages/serviced/Makefile"
	atf_check -s exit:0 -o match:'PKG_DEPS.serviced.*audit' \
	    grep 'PKG_DEPS.serviced.*audit' \
	    "${src}/packages/serviced/Makefile"
	atf_check -s exit:0 -o match:'PKG_DEPS.serviced.*libucl' \
	    grep 'PKG_DEPS.serviced.*libucl' \
	    "${src}/packages/serviced/Makefile"
	atf_check -s exit:0 -o match:'PKG_DEPS.libcapbundle.*libucl' \
	    grep 'PKG_DEPS.libcapbundle.*libucl' \
	    "${src}/packages/libcapbundle/Makefile"
	atf_check -s exit:0 -o match:'_DP_service=.*pthread' \
	    grep '^_DP_service' "${src}/share/mk/src.libnames.mk"
	atf_check -s exit:0 -o match:'_DP_service=.*channel' \
	    grep '^_DP_service' "${src}/share/mk/src.libnames.mk"
	atf_check -s exit:0 -o match:'lib/libcapability lib/libchannel' \
	    grep 'lib/libcapability lib/libchannel' \
	    "${src}/Makefile.inc1"
	atf_check -s exit:0 -o match:'lib/libsbuf lib/libservice lib/libshmring' \
	    grep 'lib/libsbuf lib/libservice lib/libshmring' \
	    "${src}/Makefile.inc1"
	atf_check -s exit:0 -o match:'libservice libshmring' \
	    grep '^SUBDIR_DEPEND_liblogcmp' "${src}/lib/Makefile"
	atf_check -s exit:0 -o match:'libservice libshmring' \
	    grep '^SUBDIR_DEPEND_libnetworkcmp' "${src}/lib/Makefile"
	atf_check -s exit:1 -o empty grep -E \
	    'service_protocol\\.(c|h)|SERVICE_PROTOCOL_HEADER_FIELDS' \
	    "${src}/lib/libservice/Makefile" \
	    "${src}/lib/libservice/libservice.h"
	for typed in filesystemcmp networkcmp logcmp notifycmp tracecmp; do
		atf_check -s exit:0 -o match:"${typed}_message_init" \
		    grep "${typed}_message_init" \
		    "${src}/lib/lib${typed}/${typed}.h"
		atf_check -s exit:1 -o empty grep 'service_protocol.h' \
		    "${src}/lib/lib${typed}/${typed}_protocol.h"
	done
	for suffix in '%-lib32' '%-lib' '%-dev' '%-man' '%-dbg'; do
		atf_check -s exit:0 -o match:"${suffix}" \
		    grep -F "\"${suffix}" \
		    "${src}/release/packages/generate-ucl.lua"
	done

	atf_check -s exit:0 -o match:'CAP_BINPACKAGE=.*filesystemcmp' \
	    grep 'CAP_BINPACKAGE' "${src}/usr.sbin/filesystemcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_ETCPACKAGE=.*filesystemcmp' \
	    grep 'CAP_ETCPACKAGE' "${src}/usr.sbin/filesystemcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_BINPACKAGE=.*networkcmp' \
	    grep 'CAP_BINPACKAGE' "${src}/usr.sbin/networkcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_ETCPACKAGE=.*networkcmp' \
	    grep 'CAP_ETCPACKAGE' "${src}/usr.sbin/networkcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_BINPACKAGE=.*logcmp' \
	    grep 'CAP_BINPACKAGE' "${src}/usr.sbin/logcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_ETCPACKAGE=.*logcmp' \
	    grep 'CAP_ETCPACKAGE' "${src}/usr.sbin/logcmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_BINPACKAGE=.*tracecmp' \
	    grep 'CAP_BINPACKAGE' "${src}/usr.sbin/tracecmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_ETCPACKAGE=.*tracecmp' \
	    grep 'CAP_ETCPACKAGE' "${src}/usr.sbin/tracecmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_BINPACKAGE=.*notifycmp' \
	    grep 'CAP_BINPACKAGE' "${src}/usr.sbin/notifycmp/Makefile"
	atf_check -s exit:0 -o match:'CAP_ETCPACKAGE=.*notifycmp' \
	    grep 'CAP_ETCPACKAGE' "${src}/usr.sbin/notifycmp/Makefile"
	atf_check -s exit:0 -o match:'serviced.*mode=0700.*package=filesystemcmp' \
	    grep 'serviced.*mode=0700.*package=filesystemcmp' \
	    "${src}/etc/mtree/BSD.var.dist"
	atf_check -s exit:0 -o match:'storage.*mode=0700.*package=filesystemcmp' \
	    grep 'storage.*mode=0700.*package=filesystemcmp' \
	    "${src}/etc/mtree/BSD.var.dist"
	atf_check -s exit:1 -o ignore -e ignore \
	    grep -E '(^|[[:space:]])(serviced|storage).*uname=capability' \
	    "${src}/etc/mtree/BSD.var.dist"

	for event in AUE_SERVICED_COMPONENT \
	    AUE_NETWORKCMP_POLICY AUE_FILESYSTEMCMP_POLICY AUE_LOGCMP_POLICY \
	    AUE_TRACECMP_POLICY AUE_NOTIFYCMP_POLICY
	do
		atf_check -s exit:0 -o match:"${event}" \
		    grep "${event}" "${src}/sys/bsm/audit_kevents.h"
		atf_check -s exit:0 -o match:"${event}" \
		    grep "${event}" "${src}/contrib/openbsm/etc/audit_event"
	done
	atf_check -s exit:0 -o match:'^43327:AUE_SERVICED_COMPONENT:.*:pc$' \
	    grep '^43327:AUE_SERVICED_COMPONENT:' \
	    "${src}/contrib/openbsm/etc/audit_event"
	atf_check -s exit:0 -o match:'^43329:AUE_NETWORKCMP_POLICY:.*:nt$' \
	    grep '^43329:AUE_NETWORKCMP_POLICY:' \
	    "${src}/contrib/openbsm/etc/audit_event"
	atf_check -s exit:0 -o match:'^43330:AUE_FILESYSTEMCMP_POLICY:.*:fa$' \
	    grep '^43330:AUE_FILESYSTEMCMP_POLICY:' \
	    "${src}/contrib/openbsm/etc/audit_event"
	atf_check -s exit:0 -o match:'^43331:AUE_LOGCMP_POLICY:.*:ad$' \
	    grep '^43331:AUE_LOGCMP_POLICY:' \
	    "${src}/contrib/openbsm/etc/audit_event"
	atf_check -s exit:0 -o match:'^43332:AUE_TRACECMP_POLICY:.*:ad$' \
	    grep '^43332:AUE_TRACECMP_POLICY:' \
	    "${src}/contrib/openbsm/etc/audit_event"
	atf_check -s exit:0 -o match:'^43333:AUE_NOTIFYCMP_POLICY:.*:ad$' \
	    grep '^43333:AUE_NOTIFYCMP_POLICY:' \
	    "${src}/contrib/openbsm/etc/audit_event"
	atf_check -s exit:0 -o match:'AUE_FILESYSTEMCMP_POLICY' \
	    grep AUE_FILESYSTEMCMP_POLICY \
	    "${src}/usr.sbin/filesystemcmp/filesystemcmp.c"
	atf_check -s exit:0 -o match:'AUE_NETWORKCMP_POLICY' \
	    grep AUE_NETWORKCMP_POLICY \
	    "${src}/usr.sbin/networkcmp/networkcmp.c"
	atf_check -s exit:0 -o match:'AUE_LOGCMP_POLICY' \
	    grep AUE_LOGCMP_POLICY "${src}/usr.sbin/logcmp/logcmp.c"
	atf_check -s exit:0 -o match:'AUE_TRACECMP_POLICY' \
	    grep AUE_TRACECMP_POLICY "${src}/usr.sbin/tracecmp/tracecmp.c"
	atf_check -s exit:0 -o match:'AUE_NOTIFYCMP_POLICY' \
	    grep AUE_NOTIFYCMP_POLICY "${src}/usr.sbin/notifycmp/notifycmp.c"
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
	for probe in on__demand__fail on__demand__cancel \
	    endpoint__claim endpoint__activate endpoint__withdraw; do
		atf_check -s exit:0 -o match:"probe ${probe}" \
		    grep "probe ${probe}" \
		    "${src}/usr.sbin/serviced/serviced_provider.d"
	done
	atf_check -s exit:0 -o match:'FILESYSTEMCMP_OP_SYNC' \
	    grep FILESYSTEMCMP_OP_SYNC \
	    "${src}/lib/libfilesystemcmp/filesystemcmp_protocol.h"
	atf_check -s exit:0 -o match:'filesystemcmp_sync' \
	    grep filesystemcmp_sync \
	    "${src}/lib/libfilesystemcmp/filesystemcmp.h"
	atf_check -s exit:0 -o match:'CAP_FSYNC' \
	    grep CAP_FSYNC "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:0 -o match:'audit_policy.*sync' \
	    grep -E 'audit_policy.*"sync"' \
	    "${src}/usr.sbin/filesystemcmp/filesystemcmp.c"
	for provider in \
	    "${src}/usr.sbin/serviced/serviced_provider.d" \
	    "${src}/usr.sbin/networkcmp/networkcmp_provider.d" \
	    "${src}/usr.sbin/logcmp/logcmp_provider.d" \
	    "${src}/usr.sbin/tracecmp/tracecmp_provider.d" \
	    "${src}/usr.sbin/notifycmp/notifycmp_provider.d" \
	    "${src}/usr.sbin/rebootd/rebootd_provider.d" \
	    "${src}/usr.sbin/kldmgrd/kldmgrd_provider.d" \
	    "${src}/lib/libnetworkcmp/networkcmp_provider.d" \
	    "${src}/lib/libfilesystemcmp/filesystemcmp_provider.d" \
	    "${src}/lib/liblogcmp/logcmp_provider.d" \
	    "${src}/lib/libtracecmp/tracecmp_provider.d" \
	    "${src}/lib/libnotifycmp/notifycmp_provider.d" \
	    "${src}/lib/libchannel/channel_provider.d" \
	    "${src}/lib/libshmring/shmring_provider.d"
	do
		test -s "${provider}" ||
		    atf_fail "missing DTrace provider ${provider}"
	done
	for daemon in rebootd kldmgrd; do
		for probe in session__start session__end request malformed; do
			atf_check -s exit:0 -o match:"probe ${probe}" \
			    grep "probe ${probe}" \
			    "${src}/usr.sbin/${daemon}/${daemon}_provider.d"
		done
		atf_check -s exit:0 -o match:'audit_submit' \
		    grep audit_submit \
		    "${src}/usr.sbin/${daemon}/${daemon}_main.c"
	done
}

atf_test_case component_selector_contract
component_selector_contract_head()
{
	atf_set "descr" \
	    "Typed libraries enforce one unambiguous scope per interface"
}
component_selector_contract_body()
{
	src="@SRCTOP@"

	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'SERVICE_DISCOVERY|service_discover' \
	    "${src}/lib/libservice/libservice.h" \
	    "${src}/lib/libservice/libservice.c"
	for library in networkcmp filesystemcmp; do
		atf_check -s exit:0 -o match:'service_local_component_open' \
		    grep service_local_component_open \
		    "${src}/lib/lib${library}/${library}.c"
		atf_check -s exit:1 -o empty -e empty \
		    grep '_ENV' "${src}/lib/lib${library}/${library}.h"
	done
	for library in logcmp tracecmp notifycmp; do
		atf_check -s exit:0 -o match:'service_connect' \
		    grep service_connect "${src}/lib/lib${library}/${library}.c"
		atf_check -s exit:1 -o empty -e empty \
		    grep '_ENV' \
		    "${src}/lib/lib${library}/${library}.h"
	done
	atf_check -s exit:0 -o match:'SERVICE_NETWORKCMP_ENV' \
	    grep SERVICE_NETWORKCMP_ENV \
	    "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:0 -o match:'SERVICE_FILESYSTEMCMP_ENV' \
	    grep SERVICE_FILESYSTEMCMP_ENV \
	    "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'SERVICE_(LOG|TRACE|NOTIFY)CMP_ENV' \
	    "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'component_session\.h|service_bootstrap\.h' \
	    "${src}/lib/libservice/Makefile"
	atf_check -s exit:0 -o match:'component_indices' \
	    grep component_indices "${src}/usr.sbin/serviced/execute.c"
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'implements|LOCAL_THEN_GLOBAL|component.*provider' \
	    "${src}/lib/libcapbundle/libcapbundle.h" \
	    "${src}/lib/libcapbundle/serviced_manifest.h"
}

atf_test_case serviced_channel_layering
serviced_channel_layering_head()
{
	atf_set "descr" \
	    "serviced control traffic uses libchannel framing, correlation, ownership, and backpressure"
}
serviced_channel_layering_body()
{
	src="@SRCTOP@"
	manager="${src}/usr.sbin/serviced"

	atf_check -s exit:0 -o match:'LIBADD=.*channel' \
	    grep '^LIBADD' "${manager}/Makefile"
	atf_check -s exit:0 -o match:'channel_create' \
	    grep channel_create "${manager}/svc_proto.c"
	atf_check -s exit:0 -o match:'channel_send_reply' \
	    grep channel_send_reply "${manager}/svc_proto.c"
	atf_check -s exit:0 -o match:'struct channel_message.*request' \
	    grep 'struct channel_message.*request' "${manager}/on_demand.c"
	atf_check -s exit:0 -o match:'svc_channel_send_event' \
	    grep svc_channel_send_event "${manager}/naming.c"
	atf_check -s exit:1 -o empty -e empty \
	    grep MAC_CAPABILITY_SENDMSG \
	    "${manager}/svc_proto.c" "${manager}/on_demand.c" \
	    "${manager}/naming.c"
	atf_check -s exit:1 -o empty -e empty \
	    grep MAC_CAPABILITY_RECVMSG \
	    "${manager}/on_demand.c" "${manager}/naming.c"
	atf_check -s exit:0 -o match:'svc_channel_rebind' \
	    grep svc_channel_rebind "${manager}/reload.c"
	atf_check -s exit:0 -o match:'EVFILT_WRITE' \
	    grep EVFILT_WRITE "${manager}/startup.c"
}

atf_init_test_cases()
{
	atf_add_test_case examples_verify
	atf_add_test_case pkgbase_default_identity
	atf_add_test_case pkgbase_component_metadata
	atf_add_test_case component_selector_contract
	atf_add_test_case serviced_channel_layering
}
