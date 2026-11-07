#
# libdq tests: the record walkers and typed accessors (no device), and
# dq_serve_file() answering every stage 1b-i event from a backing file
# (needs the dq(4) device and root; skipped without /dev/dq).
#
PACKAGE=	dq-tests
TESTSDIR=	${TESTSBASE}/lib/libdq

ATF_TESTS_C=	libdq_test

CFLAGS+=	-I${SRCTOP}/sys -I${.CURDIR}/..
LIBADD=		dq pthread

WARNS?=		6

.include <bsd.test.mk>
