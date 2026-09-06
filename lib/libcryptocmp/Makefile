.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	cryptocmp
SHLIB_MAJOR=	1
MAN=	libcryptocmp.3
MLINKS+=	libcryptocmp.3 cryptocmp_open.3
MLINKS+=	libcryptocmp.3 cryptocmp_close.3
MLINKS+=	libcryptocmp.3 cryptocmp_generate.3
MLINKS+=	libcryptocmp.3 cryptocmp_generate_key.3
MLINKS+=	libcryptocmp.3 cryptocmp_digest.3
MLINKS+=	libcryptocmp.3 cryptocmp_random.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_create.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_lease.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_rotate.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_delete.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_stat.3
MLINKS+=	libcryptocmp.3 cryptocmp_named_list.3
SRCS=	cryptocmp.c
INCS=	cryptocmp.h cryptocmp_protocol.h
LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests
.include <bsd.lib.mk>
