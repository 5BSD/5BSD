#
# libdqtest: the support library of the DescriptorQueue tests.  The
# controller harness (dqt_harness.c), queue access (dqt_access.c), saved
# global state (dqt_sysctl.c) and the served-tree harness (dqt_tree.c) that
# tests/sys/dq links; never installed.
# lib/libdq/tests compiles dqt_access.c itself: lib/ and tests/ are built in
# parallel, so it cannot rely on this archive existing.
#
LIB=		dqtest
INTERNALLIB=
SRCS=		dqt_access.c \
		dqt_fd.c \
		dqt_harness.c \
		dqt_sysctl.c \
		dqt_tree.c

CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libdq

WARNS?=		6

.include <bsd.lib.mk>
