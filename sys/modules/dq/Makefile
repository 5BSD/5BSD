.PATH: ${SRCTOP}/sys/dev/dq

PACKAGE=	dq
KMOD=	dq
SRCS=	dq_dev.c dq_queue.c dq_file.c dq_observer.c dq_observe.c
SRCS+=	bus_if.h device_if.h vnode_if.h opt_dq.h

# The module is the device: compiled standalone it is still DEV_DQ.
opt_dq.h:
	echo "#define DEV_DQ 1" > ${.TARGET}

.include <bsd.kmod.mk>
