PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/netgraph
BINDIR=		${TESTSDIR}

TAP_TESTS_SH+=	ng_macfilter_test

# Serialize tests since some share netgraph node names.
TEST_METADATA+=	is_exclusive=true
TEST_METADATA+=	required_user="root"
TEST_METADATA.ng_macfilter_test+=	required_programs="perl"

ATF_TESTS_C+=	basic		\
		bridge		\
		hub		\
		ksocket		\
		socket		\
		vhci_l2cap_test	\
		vlan_rotate

ATF_TESTS_SH+=	eiface_test
ATF_TESTS_SH+=	vhci_test

TEST_METADATA.vhci_test+=	required_programs="hccontrol ngctl vhcitool"

SRCS.basic=	basic.c util.c
SRCS.bridge=	bridge.c util.c
SRCS.hub=	hub.c util.c
SRCS.socket=	socket.c
SRCS.vhci_l2cap_test=	vhci_l2cap_test.c vhci_harness.c
SRCS.vlan_rotate=vlan_rotate.c util.c

LIBADD+=	netgraph

# vhci_l2cap_test compiles against the kernel Bluetooth headers.
CFLAGS.vhci_l2cap_test.c+=	-I${SRCTOP}/sys
CFLAGS.vhci_harness.c+=		-I${SRCTOP}/sys

.include <bsd.test.mk>
