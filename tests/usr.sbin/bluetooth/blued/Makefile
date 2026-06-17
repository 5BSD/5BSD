PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/usr.sbin/bluetooth/blued
BINDIR=		${TESTSDIR}

ATF_TESTS_C+=	smp_crypto_test
ATF_TESTS_C+=	att_test
ATF_TESTS_C+=	conn_test
ATF_TESTS_C+=	ctl_test
ATF_TESTS_C+=	peripheral_test

SRCS.smp_crypto_test=	smp_crypto_test.c
SRCS.att_test=		att_test.c
SRCS.conn_test=		conn_test.c
SRCS.ctl_test=		ctl_test.c
SRCS.peripheral_test=	peripheral_test.c

CFLAGS+=	-I${SRCTOP}/usr.sbin/bluetooth/blued
CFLAGS+=	-I${SRCTOP}/sys

.PATH:		${SRCTOP}/usr.sbin/bluetooth/blued
SRCS.smp_crypto_test+=	smp.c
SRCS.att_test+=		att.c att_server.c
SRCS.peripheral_test+=	att.c att_server.c
SRCS.conn_test+=	conn.c
SRCS.ctl_test+=		ctl.c conn.c

LIBADD+=	bluetooth crypto
LIBADD.ctl_test+=	pthread

.include <bsd.test.mk>
