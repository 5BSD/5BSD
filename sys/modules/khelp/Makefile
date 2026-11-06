SUBDIR=	

# Tied builds use the configured kernel's resolved options. Standalone builds
# retain the full family, and ALL_MODULES explicitly requests every producer.
.include <kmod.opts.mk>

.if defined(ALL_MODULES) || !defined(KERNBUILDDIR) || ${KERN_OPTS:MTCP_HHOOK} != ""
SUBDIR+=	h_ertt
.endif

.include <bsd.subdir.mk>
