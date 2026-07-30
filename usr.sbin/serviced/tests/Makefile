.include <src.opts.mk>

PACKAGE=	serviced-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/serviced

.PATH: ${SRCTOP}/usr.sbin/oracled/tests
.PATH: ${SRCTOP}/lib/libservice/tests

ATF_TESTS_SH+=	serviced_naming_test
ATF_TESTS_SH+=	serviced_svc_test
ATF_TESTS_SH+=	serviced_integration_test
ATF_TESTS_SH+=	serviced_dynamic_claims_test
ATF_TESTS_SH+=	bundle_integration_test
ATF_TESTS_SH+=	component_examples_test
ATF_TESTS_SH_SED_component_examples_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_component_examples_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

${PACKAGE}FILES+=	test_helpers.sh
${PACKAGE}FILES+=	capd_test_harness.sh
${PACKAGE}FILES+=	CapabilityKyuafile
${PACKAGE}FILES+=	run_oracle_serviced_capability_tests.sh
${PACKAGE}FILESMODE_run_oracle_serviced_capability_tests.sh=	0555

PROGS+=		capd_test_guardian
PROGS+=		capd_service_fixture
PROGS+=		capd_protocol_fixture
BINDIR=		${TESTSDIR}

LIBADD.capd_service_fixture+=	service
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/sys

LIBADD.capd_protocol_fixture+=	service
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/usr.sbin/kldmgrd
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/usr.sbin/rebootd

.include <bsd.test.mk>
