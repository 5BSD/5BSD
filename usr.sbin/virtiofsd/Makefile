.include <src.opts.mk>

PROG=	virtiofsd
PACKAGE=	bhyve

MAN=	virtiofsd.8

.PATH:	${SRCTOP}/usr.sbin/bhyve

SRCS=	virtiofsd.c \
	virtiofsd_export.c \
	virtiofsd_fuse.c \
	virtiofsd_handle.c \
	virtiofsd_server.c \
	virtiofsd_session.c \
	virtio_fs_backend.c \
	virtio_fs_backend_io.c \
	virtio_fs_outbox.c

CFLAGS+=	-I${SRCTOP}/usr.sbin/bhyve
LIBADD=	pthread

.include <bsd.prog.mk>
