.include <src.opts.mk>

PACKAGE=	serviced-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/serviced

.PATH: ${SRCTOP}/usr.sbin/oracled/tests
.PATH: ${SRCTOP}/lib/libservice/tests
.PATH: ${SRCTOP}/usr.sbin/serviced

ATF_TESTS_SH+=	serviced_naming_test
ATF_TESTS_SH+=	serviced_svc_test
ATF_TESTS_SH+=	serviced_integration_test
ATF_TESTS_SH+=	serviced_dynamic_claims_test
ATF_TESTS_SH+=	bundle_integration_test
ATF_TESTS_SH+=	component_examples_test
ATF_TESTS_SH+=	component_integration_test
ATF_TESTS_SH_SED_component_examples_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_component_examples_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_component_integration_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_component_integration_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

${PACKAGE}FILES+=	test_helpers.sh
${PACKAGE}FILES+=	capd_test_harness.sh
${PACKAGE}FILES+=	CapabilityKyuafile
${PACKAGE}FILES+=	run_oracled_serviced_capability_tests.sh
${PACKAGE}FILESMODE_run_oracled_serviced_capability_tests.sh=	0555

# ATF shell programs execute from the object directory before installation.
# Keep their shared harnesses beside them so raw object-tree test runs are as
# reliable as installed /usr/tests runs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/test_helpers.sh: ${.CURDIR}/test_helpers.sh
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/capd_test_harness.sh: \
    ${SRCTOP}/usr.sbin/oracled/tests/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/test_helpers.sh ${.OBJDIR}/capd_test_harness.sh
CLEANFILES+=	test_helpers.sh capd_test_harness.sh
.endif

PROGS+=		capd_test_guardian
PROGS+=		capd_service_fixture
PROGS+=		capd_protocol_fixture
PROGS+=		component_fixture
ATF_TESTS_C+=	on_demand_test
ATF_TESTS_C+=	fd_budget_test
ATF_TESTS_C+=	launch_limits_test
ATF_TESTS_C+=	manifest_compare_test
ATF_TESTS_C+=	bundle_selection_test
ATF_TESTS_C+=	storage_lifecycle_test
ATF_TESTS_C+=	rc_ingest_test
BINDIR=		${TESTSDIR}

# rc_ingest_test compiles the parser directly (pure logic, no daemon deps).
# rc_ingest.c comes from the serviced source dir via .PATH above; referencing
# it by basename keeps its object in the objdir (an absolute ${SRCTOP} path in
# SRCS would place the object inside $SRCTOP, which objdir builds forbid).
SRCS.rc_ingest_test=	rc_ingest_test.c rc_ingest.c
CFLAGS.rc_ingest_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.rc_ingest_test+=	-I${SRCTOP}/lib/libcapbundle

CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/liboraclert

LIBADD.capd_service_fixture+=	capability channel service pthread
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libcapability
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libchannel
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/sys


LIBADD.component_fixture+=	filesystemcmp logcmp networkcmp notify tracecmp service pthread
CFLAGS.component_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.component_fixture+=	-I${SRCTOP}/lib/libfilesystemcmp
CFLAGS.component_fixture+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS.component_fixture+=	-I${SRCTOP}/lib/libnetworkcmp
CFLAGS.component_fixture+=	-I${SRCTOP}/lib/libnotify
CFLAGS.component_fixture+=	-I${SRCTOP}/lib/libtracecmp
CFLAGS.component_fixture+=	-I${SRCTOP}/sys

CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libcapbundle
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libchannel
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/liboraclert
CFLAGS.on_demand_test+=		-I${SRCTOP}/sys
CFLAGS.on_demand_test+=		-ffunction-sections -fdata-sections
LDFLAGS.on_demand_test+=	-Wl,--gc-sections
CFLAGS.fd_budget_test+=	-I${SRCTOP}/sys
CFLAGS.launch_limits_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.launch_limits_test+=	-I${SRCTOP}/sys
SRCS.manifest_compare_test=	manifest_compare_test.c manifest_compare.c
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/sys
SRCS.bundle_selection_test=	bundle_selection_test.c bundle_selection.c
CFLAGS.bundle_selection_test+=	-I${SRCTOP}/usr.sbin/serviced
SRCS.storage_lifecycle_test=	storage_lifecycle_test.c storage_lifecycle.c
CFLAGS.storage_lifecycle_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.storage_lifecycle_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.storage_lifecycle_test+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.storage_lifecycle_test+=	-I${SRCTOP}/sys

.include <bsd.test.mk>
