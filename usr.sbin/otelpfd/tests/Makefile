PACKAGE=	otel-tests

ATF_TESTS_C=	pfstat_test
SRCS.pfstat_test=	pfstat_test.c pfstat.c
ATF_TESTS_SH=	otelpfd_test

# Replay-record generator for otelpfd -f.
PROGS+=		mkpfstatus
BINDIR_mkpfstatus=	${TESTSDIR}
MAN.mkpfstatus=

.PATH:		${.CURDIR:H}
CFLAGS+=	-I${.CURDIR:H} -I${SRCTOP}/lib/libotelexport
LIBADD.pfstat_test+=	otelexport

.include <bsd.test.mk>
