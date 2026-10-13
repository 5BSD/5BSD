.include "${SRCTOP}/sys/conf/kern.opts.mk"

SUBDIR=	envy24 envy24ht hda hdsp hdspe
SUBDIR+=	spicds driver uaudio dummy

.if ${MACHINE_CPUARCH} == "powerpc"
SUBDIR+=	ai2s davbus
.endif

.include <bsd.subdir.mk>
