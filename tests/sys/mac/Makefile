TESTSDIR=	${TESTSBASE}/sys/mac

ATF_TESTS_C+=	mac_test_hooks_test
TESTS_SUBDIRS+=	bsdextended
TESTS_SUBDIRS+=	ipacl
TESTS_SUBDIRS+=	portacl

TEST_METADATA.mac_test_hooks_test+=	required_kmods="mac_test_hooks"
TEST_METADATA.mac_test_hooks_test+=	required_user="root"
TEST_METADATA.mac_test_hooks_test+=	is_exclusive=true

.include <bsd.test.mk>
