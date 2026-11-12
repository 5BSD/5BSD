TESTSDIR=	${TESTSBASE}/sys/mqueue

ATF_TESTS_C=	mqueuefs_readdir_test
ATF_TESTS_SH=	mqueue_test

# Directory offsets in mqueuefs count entries, so queues that other tests
# create or remove while a listing is compared would move them.
TEST_METADATA.mqueuefs_readdir_test+=	is_exclusive="true"

BINDIR=		${TESTSDIR}

CFLAGS+=	-I${SRCTOP}/tests

PROGS+=		mqtest1
PROGS+=		mqtest2
PROGS+=		mqtest3
PROGS+=		mqtest4
PROGS+=		mqtest5

LIBADD+=	rt

.include <bsd.test.mk>
