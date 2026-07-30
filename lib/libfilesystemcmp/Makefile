.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	filesystemcmp
SHLIB_MAJOR=	1
MAN=	libfilesystemcmp.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_open.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_hello.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_open_root.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_lookup.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_open_handle.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_create.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_pread.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_pwrite.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_stat.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_unlink.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_rename.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_close_handle.3

SRCS=	filesystemcmp.c
INCS=	filesystemcmp.h filesystemcmp_protocol.h

LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	filesystemcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
