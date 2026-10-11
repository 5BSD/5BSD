# Explicit test fixture; never part of the system kernel/module packages.
KMOD= mac_capability_test_keystore
SRCS= mac_capability_test_keystore.c
CFLAGS+= -I${SRCTOP}/sys/dev/mac_capability -I${.CURDIR}/../include
.if make(install) || make(realinstall) || make(package)
.error Capability fixtures are test-only; load the built .ko from its object directory
.endif
.include <bsd.kmod.mk>
