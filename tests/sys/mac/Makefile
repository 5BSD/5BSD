TESTSDIR=	${TESTSBASE}/sys/mac

ATF_TESTS_C+=	mac_test_hooks_test
ATF_TESTS_SH+=	fastpath_test
TESTS_SUBDIRS+=	do
TESTS_SUBDIRS+=	portacl

CFLAGS.mac_test_hooks_test+=	-I${SRCTOP}/sys -I${SRCTOP}/sys/dev/mac_capability \
	-I${SRCTOP}/lib/libchannel
LIBADD.mac_test_hooks_test+=	channel
TEST_METADATA.mac_test_hooks_test+=	required_kmods="mac_test_hooks"
TEST_METADATA.mac_test_hooks_test+=	required_user="root"
TEST_METADATA.mac_test_hooks_test+=	is_exclusive=true
TEST_METADATA.fastpath_test+=	required_user="root"
TEST_METADATA.fastpath_test+=	is_exclusive=true

.include <bsd.test.mk>
