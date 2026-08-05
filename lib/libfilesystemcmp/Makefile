.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	filesystemcmp
SHLIB_MAJOR=	1
MAN=	libfilesystemcmp.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_open.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_close.3
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
MLINKS+=libfilesystemcmp.3 filesystemcmp_sync.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_dup.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_context_open.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_context_close.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_chdir.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_getcwd.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_lookup.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_create.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_unlink.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_rename.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_pread.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_pwrite.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_stat.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_sync.3
MLINKS+=libfilesystemcmp.3 filesystemcmp_path_close_handle.3

SRCS=	filesystemcmp.c filesystemcmp_path.c
INCS=	filesystemcmp.h filesystemcmp_protocol.h filesystemcmp_server.h

LIBADD=	pthread service
CFLAGS+=	-I${SRCTOP}/lib/libservice
STATIC_CFLAGS+=	${PICFLAG}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.if ${MK_DTRACE} != "no"
SRCS+=	filesystemcmp_provider.d
CFLAGS+=	-I${.OBJDIR} -DWITH_DTRACE
.endif

.include <bsd.lib.mk>
