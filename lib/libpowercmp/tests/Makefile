PACKAGE=	libpowercmp-tests
TESTSDIR=	${TESTSBASE}/lib/libpowercmp

CFLAGS+=	-I${SRCTOP}/lib/libpowercmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	protocol_test
SRCS.protocol_test=	protocol_test.c powercmp.c
NO_SHARED.protocol_test=	yes
LIBADD.protocol_test+=	service

.PATH: ${SRCTOP}/lib/libpowercmp

ATF_TESTS_C+= client_test
NO_SHARED.client_test= yes
LIBADD.client_test+= service

ATF_TESTS_C+= constructor_test
NO_SHARED.constructor_test= yes
LIBADD.constructor_test+= service

.include <bsd.test.mk>
