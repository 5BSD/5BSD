PROGS= oes_fixture
SRCS.oes_fixture= oes_fixture.c coalition_fixture.c oes_factory.c oes_session.c
.PATH: ${SRCTOP}/usr.sbin/BSDFilesystem
CFLAGS+= -I${SRCTOP}/sys -I${SRCTOP}/lib/liboes \
    -I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libchannel \
    -I${SRCTOP}/lib/libcapsulert \
    -I${SRCTOP}/usr.sbin/BSDFilesystem
# oes_session.c serves bsd.oes.v1; its generated code links from liboes.
CFLAGS+= -I${FIDLGEN.oes_broker} -I${SRCTOP}/lib/libfidl/include
LIBADD.oes_fixture= oes service channel fidl_bsd
NO_SHARED= yes
MAN=
FIDL_BINDINGS+= oes_broker
FIDL_SCHEMAS.oes_broker= lib/libfidl/tests/zx.fidl lib/liboes/oes_broker.fidl
FIDL_LIBRARY.oes_broker= bsd.oes.v1
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"
.include <bsd.progs.mk>
