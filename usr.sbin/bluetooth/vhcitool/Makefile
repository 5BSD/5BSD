# Virtual HCI controller tool.

.PATH: ${SRCTOP}/tests/usr.sbin/bluetooth/blued

PACKAGE=	bluetooth
PROG=		vhcitool
MAN=		vhcitool.8

# hci_emulator.c is the shared, transport-agnostic controller "brain" also
# built into the blued test suite; vhcitool binds it to the /dev/vhciN
# kernel endpoint.  Building it here (rather than duplicating it) keeps the
# tool and the tests on one spec-oracle implementation.
SRCS=		vhcitool.c hci_emulator.c

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/tests/usr.sbin/bluetooth/blued

WARNS?=		3

LIBADD=		netgraph

.include <bsd.prog.mk>
