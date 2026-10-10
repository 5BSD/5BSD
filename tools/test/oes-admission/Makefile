PROGS= oes_fixture
SRCS.oes_fixture= oes_fixture.c coalition_fixture.c oes_factory.c oes_session.c
.PATH: ${SRCTOP}/usr.sbin/BSDFilesystem
CFLAGS+= -I${SRCTOP}/sys -I${SRCTOP}/lib/liboes \
    -I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libchannel \
    -I${SRCTOP}/lib/libcapsulert \
    -I${SRCTOP}/usr.sbin/BSDFilesystem
LIBADD.oes_fixture= oes service channel
NO_SHARED= yes
MAN=
.include <bsd.progs.mk>
