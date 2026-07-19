.include <src.opts.mk>

#
# libblemesh: the Bluetooth Mesh (BLE-mesh) protocol library.
#
# The library identity is "blemesh" (produces libblemesh.so.1 / libblemesh.a),
# consistent with the sibling libble.  The source files and public symbols
# keep the mesh_* prefix for now; a coordinated rename pass moves the source
# directory (lib/libmesh -> lib/libblemesh) and the symbol prefix later, so
# the ~20 in-flight test wirings can move in a single step.
#
LIB=		blemesh
SHLIB_MAJOR=	1

VERSION_MAP=	${.CURDIR}/Version.map

CFLAGS+=	-I${.CURDIR}

#
# The full Phase 1-9 mesh stack: crypto, the network / transport / access
# layers, the foundation (Configuration, Health) and application (Generic)
# models, provisioning, the secure-network beacon, IV Update, Replay
# Protection, Key Refresh, the Proxy / Friend / Relay features, and the
# in-process multi-node network simulator that composes them end to end.
#
SRCS=		mesh_crypto.c \
		mesh_net.c \
		mesh_transport.c \
		mesh_access.c \
		mesh_cfg_model.c \
		mesh_cfg_v11.c \
		mesh_df.c \
		mesh_heartbeat.c \
		mesh_health_model.c \
		mesh_generic.c \
		mesh_sensor.c \
		mesh_lighting.c \
		mesh_lighting_lc.c \
		mesh_time_scene.c \
		mesh_provision.c \
		mesh_beacon.c \
		mesh_iv.c \
		mesh_rpl.c \
		mesh_key_refresh.c \
		mesh_proxy.c \
		mesh_friend.c \
		mesh_lpn.c \
		mesh_provisioner.c \
		mesh_remote_prov.c \
		mesh_manager.c \
		mesh_relay.c \
		mesh_sim.c

INCS=		mesh_access.h \
		mesh_beacon.h \
		mesh_cfg_model.h \
		mesh_cfg_v11.h \
		mesh_crypto.h \
		mesh_df.h \
		mesh_heartbeat.h \
		mesh_friend.h \
		mesh_generic.h \
		mesh_sensor.h \
		mesh_lighting.h \
		mesh_time_scene.h \
		mesh_health_model.h \
		mesh_iv.h \
		mesh_key_refresh.h \
		mesh_lpn.h \
		mesh_manager.h \
		mesh_net.h \
		mesh_probes.h \
		mesh_provision.h \
		mesh_provisioner.h \
		mesh_remote_prov.h \
		mesh_proxy.h \
		mesh_relay.h \
		mesh_rpl.h \
		mesh_sim.h \
		mesh_transport.h

# ECDH P-256 (provisioning), AES-CMAC / AES-CCM (crypto, beacon): libcrypto.
LIBADD=		crypto

PACKAGE=	bluetooth

MAN=		libblemesh.3

WARNS?=		6

#
# USDT provider: the `mesh` DTrace provider (mesh_provider.d, 34 probes).
#
# Whenever DTrace is enabled we generate the provider header (dtrace -h ->
# mesh_provider.h) so the layer .c files can #include it and add probe call
# sites; -I${.OBJDIR} puts that generated header on the search path.
#
# The provider OBJECT (dtrace -G, driven by a .d in SRCS) can only be linked
# once at least one .c actually references a probe -- dtrace(1) aborts with
# "No probe sites found for declared provider" otherwise.  The probe call
# sites land in a later instrumentation wave; until then the -G link is gated
# behind MESH_DTRACE_PROBES so this library builds clean today.  That wave
# only has to (1) add the probe call sites and (2) build with
# -DMESH_DTRACE_PROBES (e.g. make MESH_DTRACE_PROBES=1).
#
#
# The `mesh` USDT provider object is linked by adding mesh_provider.d to SRCS
# (dtrace -G), exactly like blued does with blued_provider.d.  The layer .c
# files reference the probes through mesh_probes.h using raw DTRACE_PROBE
# macros, so no generated provider header is required.  dtrace(1) aborts with
# "No probe sites found for declared provider" unless at least one .c actually
# fires a probe, so the -G link is gated behind MESH_DTRACE_PROBES, which also
# selects the DTrace backend of mesh_probes.h.  Build it with
# `make MESH_DTRACE_PROBES=1` (requires MK_DTRACE != no).
#
.if ${MK_DTRACE} != "no" && defined(MESH_DTRACE_PROBES)
SRCS+=		mesh_provider.d
CFLAGS+=	-DMESH_DTRACE_PROBES
.endif

.include <bsd.lib.mk>
