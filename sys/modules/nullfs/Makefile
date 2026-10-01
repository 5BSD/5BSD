.PATH: ${SRCTOP}/sys/fs/nullfs

KMOD=	nullfs
EXPORT_SYMS= null_vnodeops null_vnodeops_no_unp_bypass
SRCS=	vnode_if.h \
	null_subr.c null_vfsops.c null_vnops.c

.include <bsd.kmod.mk>
