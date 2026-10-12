PACKAGE= oes
TESTSDIR= ${TESTSBASE}/lib/liboes
ATF_TESTS_C+= ownership_test path_test broker_protocol_test broker_client_test
.PATH: ${SRCTOP}/lib/liboes
CFLAGS+= -I${SRCTOP}/lib/liboes -I${SRCTOP}/sys -I${SRCTOP}/lib/libservice
# broker_client_test runs broker.c against a scripted bsd.oes.v1 connection.
CFLAGS.broker_client_test+= -I${FIDLGEN.oes_broker} \
	-I${SRCTOP}/lib/libfidl/include -I${SRCTOP}/lib/libchannel
LIBADD.broker_client_test= service fidl_bsd
NO_SHARED.broker_client_test= yes

# Bindings generated at build time (fidl-bindings.mk); only the headers are
# used here.
FIDL_BINDINGS+=	oes_broker
FIDL_SCHEMAS.oes_broker=	lib/libfidl/tests/zx.fidl \
	lib/liboes/oes_broker.fidl
FIDL_LIBRARY.oes_broker=	bsd.oes.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>
