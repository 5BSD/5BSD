.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	networkcmp
SHLIB_MAJOR=	1
MAN=	libnetworkcmp.3
MLINKS+=libnetworkcmp.3 networkcmp_hello.3
MLINKS+=libnetworkcmp.3 networkcmp_connect.3
MLINKS+=libnetworkcmp.3 networkcmp_connect_ex.3
MLINKS+=libnetworkcmp.3 networkcmp_udp.3
MLINKS+=libnetworkcmp.3 networkcmp_resolve.3
MLINKS+=libnetworkcmp.3 networkcmp_getaddrinfo.3
MLINKS+=libnetworkcmp.3 networkcmp_freeaddrinfo.3
MLINKS+=libnetworkcmp.3 networkcmp_client_open.3
MLINKS+=libnetworkcmp.3 networkcmp_client_limits.3
MLINKS+=libnetworkcmp.3 networkcmp_client_close.3

SRCS=	networkcmp.c
INCS=	networkcmp.h networkcmp_protocol.h networkcmp_server.h

LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/sys
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	networkcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
