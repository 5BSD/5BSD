PACKAGE=	netmap-tests
TESTSDIR=	${TESTSBASE}/lib/libnetmap

ATF_TESTS_C+=	libnetmap_cap_test
LIBADD.libnetmap_cap_test+=	netmap
CFLAGS.libnetmap_cap_test+=	-I${SRCTOP}/lib/libnetmap
CFLAGS.libnetmap_cap_test+=	-I${SRCTOP}/sys

.include <bsd.test.mk>
