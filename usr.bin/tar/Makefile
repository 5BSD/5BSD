.include <src.opts.mk>

.include "${SRCTOP}/lib/libarchive/Makefile.inc"

PACKAGE=	runtime
PROG=	bsdtar

.PATH: ${_LIBARCHIVEDIR}/tar
SRCS=	bsdtar.c	\
	cmdline.c	\
	creation_set.c	\
	read.c		\
	subst.c		\
	util.c		\
	write.c

.PATH: ${_LIBARCHIVEDIR}/libarchive_fe
SRCS+=	lafe_err.c	\
	line_reader.c	\
	passphrase.c

LIBADD=	archive

CFLAGS+=	-DBSDTAR_VERSION_STRING=\"${LIBARCHIVE_VERSION_ONLY_STRING}\"
CFLAGS+=	-I${_LIBARCHIVEDIR}/tar

SYMLINKS=	bsdtar ${BINDIR}/tar
MLINKS=	bsdtar.1 tar.1

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	archiveop_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
