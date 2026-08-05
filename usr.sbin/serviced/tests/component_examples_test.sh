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

	for package in auditbrokerd auditbrokerd-tests \
	    localfilesystem localfilesystem-tests logd logd-tests \
	    kldmgrd kldmgrd-tests rebootd rebootd-tests \
	    bsdnotify bsdnotify-tests \
	    traced traced-tests \
	    localnetwork \
	    localnetwork-tests \
	    libauditcmp libauditcmp-tests libcapability libcapability-tests \
	    libchannel libchannel-tests \
	    libservice libservice-tests \
	    libfilesystemcmp libfilesystemcmp-tests \
	    libkldmgr libkldmgr-tests librebootctl librebootctl-tests \
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
	test -s "${src}/packages/liboraclectl-tests/Makefile" ||
	    atf_fail "missing liboraclectl-tests pkgbase metadata"
	atf_check -s exit:0 -o match:'WORLDPACKAGE=.*liboraclectl-tests' \
	    grep '^WORLDPACKAGE' \
	    "${src}/packages/liboraclectl-tests/Makefile"
	atf_check -s exit:0 -o match:'PKG_SETS=.*tests' \
	    grep '^PKG_SETS' "${src}/packages/liboraclectl-tests/Makefile"
	for package in auditbrokerd-tests localfilesystem-tests logd-tests \
	    kldmgrd-tests rebootd-tests \
	    traced-tests \
	    bsdnotify-tests \
	    localnetwork-tests \
	    libauditcmp-tests libcapability-tests libchannel-tests \
	    libservice-tests \
	    libkldmgr-tests librebootctl-tests \
	    liblogcmp-tests \
	    libtracecmp-tests \
	    libnotifycmp-tests \
	    libfilesystemcmp-tests libnetworkcmp-tests libshmring-tests
	do
		atf_check -s exit:0 -o match:'set = "tests"' \
		    grep 'set = ' \
		    "${src}/release/packages/ucl/${package}-all.ucl"
	done

	# Every packaged Kyua suite needs an install root in BSD.tests.dist.
	mtree="${src}/etc/mtree/BSD.tests.dist"
	for testdir in libauditcmp libkldmgr liboraclectl liboraclert \
	    librebootctl \
	    auditbrokerd filesystemcmpctl kldmgrctl kldmgrd logctl \
	    networkcmpctl notifyctl rebootctl rebootd tracectl
	do
		atf_check -s exit:0 -o ignore grep -E \
		    "^[[:space:]]{8}${testdir}$" "${mtree}"
	done

	for provider in localfilesystem localnetwork logd bsdnotify \
	    traced auditbrokerd rebootd kldmgrd; do
		atf_check -s exit:0 -o match:"PACKAGE=.*${provider}" \
		    grep '^PACKAGE' "${src}/usr.sbin/${provider}/Makefile"
	done
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libchannel/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libauditcmp/Makefile"
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
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/libkldmgr/Makefile"
	atf_check -s exit:0 -o match:'PACKAGE=lib.*LIB' \
	    grep '^PACKAGE' "${src}/lib/librebootctl/Makefile"
	for package in libauditcmp libchannel libshmring libfilesystemcmp \
	    libnetworkcmp libkldmgr librebootctl \
	    liblogcmp libnotifycmp libtracecmp localfilesystem localnetwork \
	    auditbrokerd logd bsdnotify traced kldmgrd rebootd
	do
		atf_check -s exit:0 -o match:"WORLDPACKAGE=.*${package}" \
		    grep '^WORLDPACKAGE' \
		    "${src}/packages/${package}/Makefile"
		atf_check -s exit:0 -o match:"${package}" \
		    grep -E "^[[:space:]]*${package}[[:space:]]*\\\\" \
		    "${src}/packages/Makefile"
	done
	for package in libauditcmp libchannel libshmring libfilesystemcmp \
	    libnetworkcmp libkldmgr librebootctl \
	    liblogcmp libnotifycmp libtracecmp localfilesystem localnetwork \
	    auditbrokerd logd bsdnotify traced kldmgrd rebootd
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
	atf_check -s exit:0 -o match:'PKG_DEPS.auditbrokerd.*libauditcmp' \
	    grep 'PKG_DEPS.auditbrokerd.*libauditcmp' \
	    "${src}/packages/auditbrokerd/Makefile"
	for provider in kldmgrd rebootd; do
		atf_check -s exit:0 -o match:"PKG_DEPS.${provider}.*audit" \
		    grep "PKG_DEPS.${provider}.*audit" \
		    "${src}/packages/${provider}/Makefile"
		atf_check -s exit:0 -o match:"PKG_DEPS.${provider}.*serviced" \
		    grep "PKG_DEPS.${provider}.*serviced" \
		    "${src}/packages/${provider}/Makefile"
	done
	for provider in localfilesystem localnetwork logd bsdnotify; do
		atf_check -s exit:0 -o match:"PKG_DEPS.${provider}.*auditbrokerd" \
		    grep "PKG_DEPS.${provider}.*auditbrokerd" \
		    "${src}/packages/${provider}/Makefile"
		atf_check -s exit:0 -o match:"PKG_DEPS.${provider}.*libauditcmp" \
		    grep "PKG_DEPS.${provider}.*libauditcmp" \
		    "${src}/packages/${provider}/Makefile"
	done
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
	atf_check -s exit:1 -o empty -e empty grep -E \
	    'LIBADD=.*oraclectl' "${src}/usr.sbin/servicectl/Makefile"
	atf_check -s exit:1 -o empty -e empty grep -E \
	    'PKG_DEPS\.servicectl.*liboraclectl' \
	    "${src}/packages/servicectl/Makefile"
	atf_check -s exit:1 -o empty -e empty grep -E \
	    'oraclectl_(readn|writen)' \
	    "${src}/lib/liboraclectl/oraclectl.h"
	atf_check -s exit:0 test ! -e "${src}/lib/liblwipcmp/Makefile"
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
	for typed in auditcmp filesystemcmp networkcmp logcmp notifycmp tracecmp; do
		atf_check -s exit:0 -o match:"${typed}_message_init" \
		    grep "${typed}_message_init" \
		    "${src}/lib/lib${typed}/${typed}_server.h"
		atf_check -s exit:1 -o empty \
		    grep "${typed}_message_init" \
		    "${src}/lib/lib${typed}/${typed}.h"
		atf_check -s exit:1 -o empty grep 'service_protocol.h' \
		    "${src}/lib/lib${typed}/${typed}_protocol.h"
	done
	for typed in auditcmp filesystemcmp networkcmp logcmp notifycmp tracecmp \
	    kldmgr rebootctl; do
		atf_check -s exit:0 -o match:'STATIC_CFLAGS.*PICFLAG' \
		    grep 'STATIC_CFLAGS.*PICFLAG' \
		    "${src}/lib/lib${typed}/Makefile"
	done
	for suffix in '%-lib32' '%-lib' '%-dev' '%-man' '%-dbg'; do
		atf_check -s exit:0 -o match:"${suffix}" \
		    grep -F "\"${suffix}" \
		    "${src}/release/packages/generate-ucl.lua"
	done

	for spec in \
	    'localfilesystem:FILESYSTEMCMP:localfilesystem' \
	    'localnetwork:NETWORKCMP:localnetwork' \
	    'logd:LOGCMP:logd' \
	    'traced:TRACECMP:traced' \
	    'bsdnotify:NOTIFYCMP:bsdnotify'; do
		dir=${spec%%:*}
		rest=${spec#*:}
		prefix=${rest%%:*}
		package=${rest#*:}
		atf_check -s exit:0 -o match:"${prefix}_CAP_BINPACKAGE=.*${package}" \
		    grep "${prefix}_CAP_BINPACKAGE" "${src}/usr.sbin/${dir}/Makefile"
		atf_check -s exit:0 -o match:"${prefix}_CAP_ETCPACKAGE=.*${package}" \
		    grep "${prefix}_CAP_ETCPACKAGE" "${src}/usr.sbin/${dir}/Makefile"
	done
	atf_check -s exit:0 -o match:'serviced.*mode=0700.*package=localfilesystem' \
	    grep 'serviced.*mode=0700.*package=localfilesystem' \
	    "${src}/etc/mtree/BSD.var.dist"
	atf_check -s exit:0 -o match:'storage.*mode=0700.*package=localfilesystem' \
	    grep 'storage.*mode=0700.*package=localfilesystem' \
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
	for provider in localfilesystem localnetwork logd bsdnotify; do
		case ${provider} in
		localfilesystem) source=filesystemcmp.c ;;
		localnetwork) source=networkcmp.c ;;
		logd) source=logcmp.c ;;
		bsdnotify) source=notifycmp.c ;;
		esac
		atf_check -s exit:0 -o match:'auditcmp_submit' \
		    grep auditcmp_submit \
		    "${src}/usr.sbin/${provider}/${source}"
		atf_check -s exit:1 -o empty -e empty grep 'audit_submit(' \
		    "${src}/usr.sbin/${provider}/${source}"
	done
	for event in AUE_FILESYSTEMCMP_POLICY AUE_NETWORKCMP_POLICY \
	    AUE_LOGCMP_POLICY AUE_NOTIFYCMP_POLICY; do
		atf_check -s exit:0 -o match:"${event}" grep "${event}" \
		    "${src}/usr.sbin/auditbrokerd/auditcmp_policy.c"
	done
	atf_check -s exit:0 -o match:'AUE_TRACECMP_POLICY' \
	    grep AUE_TRACECMP_POLICY "${src}/usr.sbin/traced/tracecmp.c"
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
	    "${src}/usr.sbin/localfilesystem/filesystemcmp.c"
	for provider in \
	    "${src}/usr.sbin/serviced/serviced_provider.d" \
	    "${src}/usr.sbin/localnetwork/localnetwork_provider.d" \
	    "${src}/usr.sbin/logd/logd_provider.d" \
	    "${src}/usr.sbin/traced/traced_provider.d" \
	    "${src}/usr.sbin/bsdnotify/bsdnotify_provider.d" \
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
		case ${daemon} in
		rebootd) source=rebootd_main.c ;;
		kldmgrd) source=kldmgrd_main.c ;;
		esac
		atf_check -s exit:0 -o match:'audit_submit' \
		    grep audit_submit \
		    "${src}/usr.sbin/${daemon}/${source}"
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
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'nofile|descriptor_limit|max_descriptors' \
	    "${src}/lib/libcapbundle/serviced_manifest.h"
	atf_check -s exit:0 -o match:'kern.maxfilesperproc' \
	    grep kern.maxfilesperproc \
	    "${src}/usr.sbin/serviced/fd_budget.c"
}

atf_test_case serviced_channel_layering
serviced_channel_layering_head()
{
	atf_set "descr" \
	    "serviced control traffic uses libchannel framing, correlation, ownership, and backpressure"
}

atf_test_case operational_name_contract
operational_name_contract_head()
{
	atf_set "descr" \
	    "Operational daemon, rc, package, and capability-bundle names stay coherent"
}
operational_name_contract_body()
{
	src="@SRCTOP@"
	rcscript="${src}/libexec/rc/rc.d/oracled"
	rcconf="${src}/libexec/rc/rc.conf"

	atf_check -s exit:0 -o match:'^name="oracled"$' \
	    grep '^name=' "${rcscript}"
	atf_check -s exit:0 -o match:'^rcvar="oracled_enable"$' \
	    grep '^rcvar=' "${rcscript}"
	for hook in stop reload status; do
		atf_check -s exit:0 -o match:"^oracled_${hook}\\(\\)" \
		    grep "^oracled_${hook}()" "${rcscript}"
	done
	atf_check -s exit:0 -o match:'^oracled_enable=' \
	    grep '^oracled_enable=' "${rcconf}"
	atf_check -s exit:0 -o match:'^oracled_flags=' \
	    grep '^oracled_flags=' "${rcconf}"
	atf_check -s exit:1 -o empty -e empty \
	    grep -E '^(trailbossd_enable|trailbossd_flags|wranglerd_enable|wranglerd_flags)=' "${rcconf}"

	for daemon in oracled serviced localfilesystem localnetwork logd \
	    bsdnotify traced auditbrokerd rebootd kldmgrd; do
		makefile="${src}/usr.sbin/${daemon}/Makefile"
		atf_check -s exit:0 -o match:"^PROG[[:space:]]*=.*${daemon}$" \
		    grep '^PROG' "${makefile}"
		atf_check -s exit:0 -o match:"^PACKAGE[[:space:]]*=.*${daemon}$" \
		    grep '^PACKAGE' "${makefile}"
		test -s "${src}/packages/${daemon}/Makefile" ||
		    atf_fail "missing ${daemon} pkgbase definition"
		if ! test -s "${src}/release/packages/ucl/${daemon}-all.ucl" &&
		    ! test -s "${src}/packages/${daemon}/${daemon}.ucl"; then
			atf_fail "missing ${daemon} package metadata"
		fi
	done

	for mapping in \
	    'localfilesystem:LocalFilesystem.cap' \
	    'localnetwork:LocalNetwork.cap' \
	    'logd:Log.cap' \
	    'bsdnotify:BsdNotify.cap' \
	    'traced:Trace.cap' \
	    'auditbrokerd:Audit.cap' \
	    'rebootd:Reboot.cap' \
	    'kldmgrd:Kldmgr.cap'; do
		daemon=${mapping%%:*}
		bundle=${mapping#*:}
		atf_check -s exit:0 -o match:"/Capabilities/System/${bundle}" \
		    grep '/Capabilities/System/' \
		    "${src}/usr.sbin/${daemon}/Makefile"
	done

	# Old names are not compatibility aliases: reject them at public rc and
	# deployment boundaries.  Internal protocol identifiers are deliberately
	# outside this check.
	atf_check -s exit:1 -o empty -e empty grep -E \
		'/var/run/(trailbossd|wranglerd)([./"]|$)|/var/db/wranglerd([/"]|$)|/etc/(trailbossd|logcmp|notifycmp|tracecmp|auditcmp)([.]|/|"|$)' \
	    "${rcscript}" "${rcconf}" \
	    "${src}/usr.sbin/oracled/oracled.conf" \
	    "${src}/usr.sbin/oracled/oracled.conf.5"
	atf_check -s exit:1 -o empty -e empty grep -E \
		'^\\.Xr (filesystemcmp|networkcmp|logcmp|notifycmp|tracecmp|auditcmp|trailbossd|wranglerd) 8' \
	    "${src}/lib/libfilesystemcmp/libfilesystemcmp.3" \
	    "${src}/lib/libnetworkcmp/libnetworkcmp.3" \
	    "${src}/lib/liblogcmp/liblogcmp.3" \
	    "${src}/lib/libnotifycmp/libnotifycmp.3" \
	    "${src}/lib/libtracecmp/libtracecmp.3" \
	    "${src}/lib/libauditcmp/libauditcmp.3" \
	    "${src}/lib/libkldmgr/libkldmgr.3" \
	    "${src}/lib/librebootctl/librebootctl.3"
	atf_check -s exit:0 -o match:'org.5bsd.system.reboot/rebootd' \
	    grep 'org.5bsd.system.reboot/rebootd' \
	    "${src}/usr.sbin/bsdnotify/capbundle/bsdnotify.conf"
	atf_check -s exit:1 -o empty -e empty grep -E \
	    '@OBJTOP@/usr.sbin/(filesystemcmp|networkcmp|logcmp|notifycmp|tracecmp|auditcmp)/' \
	    "${src}/usr.sbin/serviced/tests/component_integration_test.sh"
	atf_check -s exit:0 -o match:'cap_openlog.*"logd"' \
	    grep 'cap_openlog.*"logd"' \
	    "${src}/usr.sbin/logd/logcmp.c"
}

atf_test_case typed_header_boundaries
typed_header_boundaries_head()
{
	atf_set "descr" \
	    "Typed client headers exclude provider framing and provider bootstrap APIs"
}
typed_header_boundaries_body()
{
	src="@SRCTOP@"

	for library in filesystemcmp networkcmp logcmp notifycmp tracecmp \
	    auditcmp kldmgr rebootctl
	do
		client="${src}/lib/lib${library}/${library}.h"
		server="${src}/lib/lib${library}/${library}_server.h"
		makefile="${src}/lib/lib${library}/Makefile"
		test -s "${server}" ||
		    atf_fail "missing ${library} server header"
		atf_check -s exit:1 -o empty -e empty \
		    grep -E '(message_init|validate_(message|fds|request|reply|record|topic))' \
		    "${client}"
		atf_check -s exit:0 -o match:'validate_|message_init' \
		    grep -E '(message_init|validate_)' "${server}"
		atf_check -s exit:0 -o match:"${library}_server.h" \
		    grep '^INCS=' "${makefile}"
	done
	atf_check -s exit:1 -o empty -e empty \
	    grep -E 'auditcmp_client_(prepare|adopt)' \
	    "${src}/lib/libauditcmp/auditcmp.h"
	atf_check -s exit:0 -o match:'auditcmp_client_prepare' \
	    grep auditcmp_client_prepare \
	    "${src}/lib/libauditcmp/auditcmp_server.h"
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
	atf_add_test_case typed_header_boundaries
	atf_add_test_case operational_name_contract
}
