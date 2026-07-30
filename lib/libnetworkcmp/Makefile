.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	networkcmp
SHLIB_MAJOR=	1
MAN=	libnetworkcmp.3
MLINKS+=libnetworkcmp.3 networkcmp_open.3
MLINKS+=libnetworkcmp.3 networkcmp_hello.3
MLINKS+=libnetworkcmp.3 networkcmp_socket.3
MLINKS+=libnetworkcmp.3 networkcmp_bind.3
MLINKS+=libnetworkcmp.3 networkcmp_connect.3
MLINKS+=libnetworkcmp.3 networkcmp_listen.3
MLINKS+=libnetworkcmp.3 networkcmp_accept.3
MLINKS+=libnetworkcmp.3 networkcmp_setopt.3
MLINKS+=libnetworkcmp.3 networkcmp_shutdown.3
MLINKS+=libnetworkcmp.3 networkcmp_close_socket.3
MLINKS+=libnetworkcmp.3 networkcmp_resolve.3
MLINKS+=libnetworkcmp.3 networkcmp_getaddrinfo.3
MLINKS+=libnetworkcmp.3 networkcmp_freeaddrinfo.3
MLINKS+=libnetworkcmp.3 networkcmp_client_open.3
MLINKS+=libnetworkcmp.3 networkcmp_negotiate.3
MLINKS+=libnetworkcmp.3 networkcmp_attach_io.3
MLINKS+=libnetworkcmp.3 networkcmp_write.3
MLINKS+=libnetworkcmp.3 networkcmp_send_datagram.3

SRCS=	networkcmp.c
INCS=	networkcmp.h networkcmp_protocol.h netmap_bearer.h

LIBADD=	pthread service shmring
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	networkcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
