.include <bsd.init.mk>

PACKAGE=	bsdinstall-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/bsdinstall

ATF_TESTS_SH=	capabilitypolicy_test \
		config_test \
		documentation_test \
		firmware_fetch_test \
		storage_requirement_test \
		tzfspool_test

ATF_TESTS_SH_SED_documentation_test+= \
	-e 's,@SRCTOP@,${SRCTOP},g'

ATF_TESTS_SH_SED_storage_requirement_test+= \
	-e 's,@SRCTOP@,${SRCTOP},g'

.include <bsd.test.mk>
