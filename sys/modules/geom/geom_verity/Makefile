# SPDX-License-Identifier: BSD-2-Clause
# Component build only: not in the default module list or any boot policy.
.PATH: ${SRCTOP}/sys/geom/verity

KMOD=	geom_verity
SRCS=	g_verity_provider.c g_verity_io.c g_verity_verify.c g_verity_boot.c g_verity_mount.c g_verity_transition.c
SRCS+=	g_verity_provider.h g_verity_io.h g_verity_verify.h g_verity_transition.h

.include <bsd.kmod.mk>
