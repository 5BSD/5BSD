SUBDIR=	cc_newreno \
	cc_cubic \
	cc_dctcp \
	cc_htcp


# Tied builds use the configured kernel's resolved options. Standalone builds
# retain the full family, and ALL_MODULES explicitly requests every producer.
.include <kmod.opts.mk>

.if defined(ALL_MODULES) || !defined(KERNBUILDDIR) || ${KERN_OPTS:MTCP_HHOOK} != ""
SUBDIR+= \
	cc_cdg \
	cc_chd \
	cc_hd \
	cc_vegas
.endif

.include <bsd.subdir.mk>
