PACKAGE=	libchannel-tests
TESTSDIR=	${TESTSBASE}/lib/libchannel
NO_SHARED=	yes

ATF_TESTS_C+=	channel_test
LIBADD.channel_test+=	channel
CFLAGS.channel_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.channel_test+=	-I${SRCTOP}/sys

.include <bsd.test.mk>
