.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	cryptodesc
SHLIB_MAJOR=	1
MAN=	libcryptodesc.3
MLINKS+=	libcryptodesc.3 cryptodesc_mint.3
MLINKS+=	libcryptodesc.3 cryptodesc_mint_generated.3
MLINKS+=	libcryptodesc.3 cryptodesc_mint_key.3
MLINKS+=	libcryptodesc.3 cryptodesc_named_create.3
MLINKS+=	libcryptodesc.3 cryptodesc_named_lease.3
MLINKS+=	libcryptodesc.3 cryptodesc_named_rotate.3
MLINKS+=	libcryptodesc.3 cryptodesc_named_delete.3
MLINKS+=	libcryptodesc.3 cryptodesc_named_stat.3
MLINKS+=	libcryptodesc.3 cryptodesc_named_list.3
MLINKS+=	libcryptodesc.3 cryptodesc_owner_list.3
MLINKS+=	libcryptodesc.3 cryptodesc_restrict.3
MLINKS+=	libcryptodesc.3 cryptodesc_revoke.3
MLINKS+=	libcryptodesc.3 cryptodesc_get_info.3
SRCS=	cryptodesc.c
INCS=	cryptodesc.h

CFLAGS+=	-I${SRCTOP}/sys

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
