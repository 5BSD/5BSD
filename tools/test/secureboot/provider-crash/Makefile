.include <src.opts.mk>
PROG= storage_crash_provider
MAN=
.PATH: ${SRCTOP}/usr.sbin/BSDFilesystem
SRCS= bsdfilesystem.c layout.c nvwalk.c request.c oes_factory.c oes_session.c crash.c
CFLAGS+= -DBSDFILESYSTEM_CRASH_TEST
CAPIMAGE_MANIFEST= ${SRCTOP}/usr.sbin/BSDFilesystem/capbundle/bsdfilesystem.ucl
.include "${SRCTOP}/usr.sbin/BSDFilesystem/Makefile.common"
.include <bsd.prog.mk>
