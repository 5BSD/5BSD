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
		mesh_bridge.c \
		mesh_df.c \
		mesh_heartbeat.c \
		mesh_health_model.c \
		mesh_generic.c \
		mesh_sensor.c \
		mesh_lighting.c \
		mesh_lighting_lc.c \
		mesh_time_scene.c \
		mesh_provision.c \
		mesh_prov_records.c \
		mesh_prov_cert.c \
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
		mesh_bridge.h \
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
		mesh_prov_records.h \
		mesh_prov_cert.h \
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

# Include the existing USDT sites in normal DTrace-enabled base libraries.
.if ${MK_DTRACE} != "no"
SRCS+=		mesh_provider.d
DTRACE_STATIC_ANCHOR= yes
CFLAGS+=	-DMESH_DTRACE_PROBES
.endif

.include <bsd.lib.mk>
