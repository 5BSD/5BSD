PACKAGE=	libchannel-tests
TESTSDIR=	${TESTSBASE}/lib/libchannel
NO_SHARED=	yes

ATF_TESTS_C+=	channel_test
# pthread (call_concurrent_channels) pulls the in-tree static libc into this
# NO_SHARED test, whose cap_clofork_limit(2) is system call 1002: on a host
# kernel older than that the test dies with SIGSYS.  Run it in a VM booted
# from the same build (tools/build/fuchsia/vm-provider.sh), as the channel
# call cases need that kernel anyway.
LIBADD.channel_test+=	channel pthread
CFLAGS.channel_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.channel_test+=	-I${SRCTOP}/sys
# Statically linked: the test's malloc/calloc wrappers inject allocation
# failures into libchannel itself.
LDFLAGS.channel_test+=	-Wl,--wrap=malloc,--wrap=calloc

# System calls per synchronous call, for ktrace(1): call_bench split|call N
PROGS+=		call_bench
BINDIR_call_bench=	${TESTSDIR}
MAN.call_bench=
LIBADD.call_bench+=	channel
CFLAGS.call_bench+=	-I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys

ATF_TESTS_SH+=	ipc_soak_test
PROGS+=		ipc_soak
BINDIR_ipc_soak=	${TESTSDIR}
MAN.ipc_soak=
LIBADD.ipc_soak+=	channel
CFLAGS.ipc_soak+=	-I${SRCTOP}/lib/libchannel -I${SRCTOP}/sys

.include <bsd.test.mk>
