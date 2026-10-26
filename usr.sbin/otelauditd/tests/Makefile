PACKAGE=	otel-tests

ATF_TESTS_C=	auditrec_test
SRCS.auditrec_test=	auditrec_test.c auditrec.c bsmgen.c
ATF_TESTS_SH=	otelauditd_test

# BSM test-trail writer for otelauditd -f.
PROGS+=		mkaudittrail
BINDIR_mkaudittrail=	${TESTSDIR}
MAN.mkaudittrail=
SRCS.mkaudittrail=	mkaudittrail.c bsmgen.c

.PATH:		${.CURDIR:H}
CFLAGS+=	-I${.CURDIR:H} -I${.CURDIR} -I${SRCTOP}/lib/libotelexport
LIBADD.auditrec_test+=	otelexport bsm
LIBADD.mkaudittrail+=	bsm

.include <bsd.test.mk>
