# Isolated VM fixture; never install or load this module on the host.
KMOD= mac_capability_test_cleanup
SRCS= cleanup_fixture.c
CFLAGS+= -I${SRCTOP}/sys/dev/mac_capability
.include <bsd.kmod.mk>
