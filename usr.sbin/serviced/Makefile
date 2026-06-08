.include <src.opts.mk>

PACKAGE=serviced
PROG=	serviced
MAN=	serviced.8
SRCS=	serviced.c bundle_registry.c caprt_direct.c depgraph.c execute.c \
	manifest.c naming.c on_demand.c oracle_client.c reload.c sctl.c \
	startup.c svc_proto.c supervisor.c
# claim_parse functions are provided by libappbundle (which compiles
# claim_parse.c from oracled/).  No need to duplicate here.
.PATH:	${SRCTOP}/usr.sbin/oracled

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/usr.sbin/oracled
CFLAGS+=	-I${SRCTOP}/lib/libappbundle
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		appbundle jail ucl util

.if ${MK_DTRACE} != "no"
SRCS+=		serviced_provider.d
CFLAGS+=	-I${.OBJDIR}
CFLAGS+=	-DWITH_DTRACE
.endif

.include <bsd.prog.mk>
