# Makefile for mrsas driver

KMOD=mrsas

.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "aarch64"
SUBDIR+= mrsas_linux
.endif
.PATH: ${SRCTOP}/sys/dev/${KMOD}

SRCS=mrsas.c mrsas_cam.c mrsas_ioctl.c mrsas_fp.c
SRCS+=  device_if.h bus_if.h pci_if.h opt_cam.h opt_scsi.h vnode_if.h

#CFLAGS+= -MRSAS_DEBUG
.include <bsd.kmod.mk>
CFLAGS+= -fgnu89-inline

clean_cscope:
	rm -f cscope*

cscope:	clean_cscope
	/usr/local/bin/cscope -b *.[ch]

cleanall:	clean clean_cscope
