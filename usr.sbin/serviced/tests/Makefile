.include <src.opts.mk>

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/usr.sbin/serviced

ATF_TESTS_SH+=	serviced_naming_test
ATF_TESTS_SH+=	serviced_svc_test
ATF_TESTS_SH+=	serviced_integration_test
ATF_TESTS_SH+=	serviced_dynamic_claims_test
ATF_TESTS_SH+=	bundle_integration_test

${PACKAGE}FILES+=	test_helpers.sh

.include <bsd.test.mk>
