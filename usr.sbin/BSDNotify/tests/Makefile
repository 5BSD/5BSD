PACKAGE=	bsdnotify-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/BSDNotify
NO_SHARED=

CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libnotify
.if !defined(PROG) || ${PROG} != "next_peer"
CFLAGS+=	-I${FIDLGEN.notify}
.endif
CFLAGS+=	-I${SRCTOP}/lib/libfidl/include
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
LIBADD.dispatcher_test+=	auditcmp channel fidl_bsd notify pthread service ucl

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
.include "${SRCTOP}/tests/srctree.mk"

# The real provider and libnotify over capability channels (plane-on tier):
# negotiation, record rules, authorization, long polls and evolution.
ATF_TESTS_C+=	session_test
SRCS.session_test=	session_test.c broker.c policy.c transport.c
CFLAGS.session_test+=	-I${SRCTOP}/lib/libauditcmp -I${SRCTOP}/lib/libchannel \
	-I${SRCTOP}/lib/liblogcmp -I${SRCTOP}/sys -Wno-unused-function
LIBADD.session_test+=	auditcmp channel fidl_bsd logcmp notify pthread service ucl
TEST_METADATA.session_test+= required_user="root" timeout="120"

# Schema evolution: next_peer is built from evolution/notify_next.fidl at
# bsd:2 (its own bindings).
PROGS+= next_peer
BINDIR_next_peer= ${TESTSDIR}
MAN.next_peer=
SRCS.next_peer= next_peer.c ${FIDLGEN_SRCS.notify_next}
CFLAGS.next_peer+= -I${FIDLGEN.notify_next}
CXXSTD.next_peer= c++20
LIBADD.next_peer= fidl_bsd channel cplusplus
WARNS.next_peer= 0
.include "${SRCTOP}/lib/libfidl/runtime-includes.mk"

# VM latency probe (tools/build/fuchsia/daemon_bench.h, vm-daemons.sh);
# libchannel is linked shared so its USDT request probes reach dtrace -c.
PROGS+= latency_bench
BINDIR_latency_bench= ${TESTSDIR}
MAN.latency_bench=
SRCS.latency_bench= latency_bench.c latency_bench_server.c broker.c policy.c transport.c
CFLAGS.latency_bench+= ${CFLAGS.session_test} -I${SRCTOP}/tools/build/fuchsia
LIBADD.latency_bench= auditcmp channel fidl_bsd logcmp notify pthread service ucl
NO_SHARED.latency_bench= no

# Static tests embed upstream codec code.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/bsdnotify-tests/fuchsia

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	notify
FIDL_SCHEMAS.notify=	lib/libnotify/notify.fidl
FIDL_LIBRARY.notify=	bsd.notify.v1
FIDL_BINDINGS+=	notify_next
FIDL_SCHEMAS.notify_next=	usr.sbin/BSDNotify/tests/evolution/notify_next.fidl
FIDL_LIBRARY.notify_next=	bsd.notify.v1
FIDL_FLAGS.notify_next=	--available bsd:2
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.PATH: ${.CURDIR}/evolution

# broker.o is shared by multiple tests; track the reserved-owner header.
broker.o: ${SRCTOP}/lib/libnotify/notify_pressure.h

.include <bsd.test.mk>
