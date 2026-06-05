.include <src.opts.mk>

PACKAGE=serviced
PROG=	serviced
MAN=	serviced.8
SRCS=	serviced.c caprt_direct.c depgraph.c execute.c manifest.c \
	naming.c oracle_client.c reload.c sctl.c svc_proto.c supervisor.c
# Shared with oracled — UCL parsers for network/jail claims
SRCS+=	claim_parse.c
.PATH:	${SRCTOP}/usr.sbin/oracled

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/usr.sbin/oracled
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		jail ucl util

.if ${MK_DTRACE} != "no"
SRCS+=		serviced_provider.d
CFLAGS+=	-I${.OBJDIR}
.endif

.include <bsd.prog.mk>
