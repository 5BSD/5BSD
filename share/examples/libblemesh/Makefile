# Example program for the libblemesh Bluetooth Mesh network-manager API.
#
# Built inside the source tree (the mesh_*.h headers are not yet installed):
#     make
#
# It links the in-tree libblemesh; run the result with ./mesh_provision_configure.

PROG=	mesh_provision_configure
MAN=

# libblemesh is registered in share/mk/src.libnames.mk as "blemesh".
LIBADD=	blemesh
CFLAGS+=	-I${SRCTOP}/lib/libmesh

# This is a standalone example, not installed as a system program.
BINDIR?=	/usr/share/examples/libblemesh

.include <bsd.prog.mk>
