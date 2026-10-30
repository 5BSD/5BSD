PACKAGE=	libtrustedzfs-tests
TESTSDIR=	${TESTSBASE}/lib/libtrustedzfs

ATF_TESTS_C+=	trustedzfs_capsicum_test trustedzfs_limit_test
LDFLAGS.trustedzfs_capsicum_test+=	-Wl,--wrap=ioctl
CFLAGS+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS+=	-I${SRCTOP}/sys
LIBADD+=	trustedzfs
NO_SHARED=	yes

.include <bsd.test.mk>
