#
# libdq tests: the record walkers and typed accessors (no device), and
# dq_serve_file() answering every stage 1b-i event from a backing file
# (needs the dq(4) device and root; skipped without /dev/dq).
# libdq_link_test links neither libdq nor libthr: it loads libdq.so.1 with
# dlopen(3) to check that the library records its own dependencies.
#
PACKAGE=	dq-tests
TESTSDIR=	${TESTSBASE}/lib/libdq

ATF_TESTS_C=	libdq_test \
		libdq_link_test

CFLAGS+=	-I${SRCTOP}/sys -I${.CURDIR}/..
LIBADD.libdq_test=	dq pthread

WARNS?=		6

.include <bsd.test.mk>
