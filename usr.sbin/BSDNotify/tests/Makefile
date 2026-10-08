PACKAGE=	bsdnotify-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDNotify
NO_SHARED=

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libnotify
# policy.c is shared by policy_test and dispatcher_test; bsd.progs.mk compiles
# a shared object with only the global flags, so its includes live here.
CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	broker_test
SRCS.broker_test=	broker_test.c broker.c
CFLAGS.broker_test+=	-I${.CURDIR}/..
LIBADD.broker_test+=	notify pthread service
.PATH:	${.CURDIR}/..

ATF_TESTS_C+=	transport_test
SRCS.transport_test=	transport_test.c transport.c
CFLAGS.transport_test+=	-I${.CURDIR}/..
LIBADD.transport_test+=	notify pthread service

ATF_TESTS_C+=	dispatcher_test
SRCS.dispatcher_test=	dispatcher_test.c broker.c transport.c policy.c
CFLAGS.dispatcher_test+=	-I${.CURDIR}/..
CFLAGS.dispatcher_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.dispatcher_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.dispatcher_test+=	-I${SRCTOP}/contrib/libucl/include
CFLAGS.dispatcher_test+=	-I${SRCTOP}/sys
CFLAGS.dispatcher_test+=	-Wno-unused-function
LIBADD.dispatcher_test+=	auditcmp channel notify pthread service ucl

ATF_TESTS_C+=	policy_test
SRCS.policy_test=	policy_test.c policy.c
CFLAGS.policy_test+=	-I${.CURDIR}/..
CFLAGS.policy_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.policy_test+=	notify ucl

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

# The shell contract cases read these source files.  Install them beneath
# ${TESTSDIR}/srctree so the installed tests do not depend on the build
# machine's source tree.
SRCTREE_FILES=	cddl/usr.sbin/bsdinstruments/profiles/capability-services.d \
		lib/libnotify/notify.c \
		lib/libnotify/notify_protocol.h \
		lib/libnotify/notify_provider.d \
		usr.sbin/BSDAudit/auditcmp_policy.c \
		usr.sbin/BSDNotify/Makefile \
		usr.sbin/BSDNotify/bsdnotify.c \
		usr.sbin/BSDNotify/bsdnotify_probes.h \
		usr.sbin/BSDNotify/bsdnotify_provider.d \
		usr.sbin/BSDNotify/capbundle/bsdnotify.conf \
		usr.sbin/BSDNotify/capbundle/bsdnotify.ucl \
		usr.sbin/BSDNotify/policy.c \
		usr.sbin/BSDNotify/policy.h \
		usr.sbin/switchboard/svc_proto.c
.for _dir in ${SRCTREE_FILES:H:O:u}
FILESGROUPS+=	SRCTREE_${_dir:S,/,_,g}
SRCTREE_${_dir:S,/,_,g}=	${SRCTREE_FILES:M${_dir}/*:N${_dir}/*/*:S,^,${SRCTOP}/,}
SRCTREE_${_dir:S,/,_,g}DIR=	${TESTSDIR}/srctree/${_dir}
SRCTREE_${_dir:S,/,_,g}PACKAGE=	${PACKAGE}
.endfor

.include <bsd.test.mk>
