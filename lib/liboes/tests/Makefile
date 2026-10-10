PACKAGE= oes
TESTSDIR= ${TESTSBASE}/lib/liboes
ATF_TESTS_C+= ownership_test path_test broker_protocol_test broker_client_test
.PATH: ${SRCTOP}/lib/liboes
CFLAGS+= -I${SRCTOP}/lib/liboes -I${SRCTOP}/sys -I${SRCTOP}/lib/libservice
LIBADD.broker_client_test= service
NO_SHARED.broker_client_test= yes
.include <bsd.test.mk>
