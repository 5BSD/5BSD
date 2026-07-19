.include <src.opts.mk>

PROG=		meshd
SRCS=		meshd.c meshd_node.c meshd_models.c meshd_config.c meshd_ctl.c \
		meshd_persist.c meshd_cfgclient.c meshd_bearer_blued.c \
		meshd_pbgatt.c meshd_proxy_gatt.c

PACKAGE=	bluetooth

MAN=		meshd.8

CONFS=		meshd.conf.sample
CONFSDIR=	${SHAREDIR}/examples/meshd

WARNS?=		6

#
# meshd is built on libblemesh (lib/libmesh) and libbluetooth.  libblemesh is
# registered in share/mk/src.libnames.mk (as "blemesh", directory lib/libmesh),
# so it is linked via LIBADD; crypto is pulled in transitively but is listed
# explicitly to match the direct link dependencies.  LIBADD only drives the
# link, so the mesh_*.h public headers still need an explicit include path
# until they are installed.
#
LIBADD=		blemesh bluetooth crypto
CFLAGS+=	-I${SRCTOP}/lib/libmesh -I${SRCTOP}/lib/libble \
		-I${SRCTOP}/usr.sbin/bluetooth/blued

.if ${MK_DTRACE} != "no" && defined(MESHD_DTRACE_PROBES)
SRCS+=		meshd_provider.d
CFLAGS+=	-DMESHD_DTRACE_PROBES
.endif

.include <bsd.prog.mk>
