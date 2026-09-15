PACKAGE=	authagentd-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/authagentd
.PATH:		${SRCTOP}/usr.sbin/authagentd

ATF_TESTS_SH+=	observability_test
ATF_TESTS_SH+=	elevate_integration_test
ATF_TESTS_C+=	elevate_test
ATF_TESTS_C+=	gate_test
ATF_TESTS_C+=	identity_test
ATF_TESTS_C+=	mint_decision_test
ATF_TESTS_C+=	provider_test

# Interactive pty driver for the elevation integration test (see the source).
PROGS+=		pty_askpass
MAN.pty_askpass=	# helper, no manual page
LIBADD.pty_askpass=	util
CFLAGS.pty_askpass=	# no daemon seam; a plain program

# Every test links the daemon object built with its testing seam
# (-DAUTHAGENTD_TESTING guards out main() and exposes the factored predicates
# plus the provider serve entry point).  The daemon's own dependencies come
# along, so mirror its include path and libraries.  All tests share the
# same flags, so they are global: the shared authagentd.c object is compiled
# once for the directory.
CFLAGS+=	-DAUTHAGENTD_TESTING
CFLAGS+=	-I${SRCTOP}/usr.sbin/authagentd
CFLAGS+=	-I${SRCTOP}/lib/libchannel
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/sys
CFLAGS.mint_decision_test+= \
	-DDEFAULT_POLICY_PATH='"${SRCTOP}/usr.sbin/authagentd/principal-policy.ucl"'

SRCS.elevate_test=		elevate_test.c authagentd.c
SRCS.gate_test=			gate_test.c authagentd.c
SRCS.identity_test=		identity_test.c authagentd.c
SRCS.mint_decision_test=	mint_decision_test.c authagentd.c
SRCS.provider_test=		provider_test.c authagentd.c

# crypt: the daemon object's in-agent password verification (ELEVATE).
LIBADD=		service channel capability capbundle crypt

ATF_TESTS_SH_SED_observability_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_observability_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_observability_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

.include <bsd.test.mk>
