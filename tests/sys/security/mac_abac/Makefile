PACKAGE=	mac-abac-tests
TESTSDIR=	${TESTSBASE}/sys/security/mac_abac

ATF_TESTS_SH+=	smoke_test
TEST_METADATA.smoke_test+=	required_user="root"
TEST_METADATA.smoke_test+=	required_kmods="mac_abac"
TEST_METADATA.smoke_test+=	is_exclusive="true"

.include <bsd.test.mk>
