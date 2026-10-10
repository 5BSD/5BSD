PACKAGE=	libchannel-tests
TESTSDIR=	${TESTSBASE}/lib/libchannel
NO_SHARED=	yes

ATF_TESTS_C+=	channel_test
LIBADD.channel_test+=	channel
CFLAGS.channel_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.channel_test+=	-I${SRCTOP}/sys

ATF_TESTS_SH+=	ipc_soak_test
PROGS+=		ipc_soak
BINDIR_ipc_soak=	${TESTSDIR}
MAN.ipc_soak=
LIBADD.ipc_soak+=	channel
CFLAGS.ipc_soak+=	-I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys

.include <bsd.test.mk>
