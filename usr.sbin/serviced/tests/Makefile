.include <src.opts.mk>

PACKAGE=	serviced-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/serviced

.PATH: ${SRCTOP}/usr.sbin/authorityd/tests
.PATH: ${SRCTOP}/lib/libservice/tests
.PATH: ${SRCTOP}/usr.sbin/serviced

ATF_TESTS_SH+=	serviced_naming_test
ATF_TESTS_SH+=	serviced_svc_test
ATF_TESTS_SH+=	serviced_integration_test
ATF_TESTS_SH+=	serviced_dynamic_claims_test
ATF_TESTS_SH+=	bundle_integration_test
ATF_TESTS_SH+=	helper_integration_test
ATF_TESTS_SH+=	service_reachability_test
ATF_TESTS_SH_SED_helper_integration_test+=	-e 's,@SRCTOP@,${SRCTOP},g'

${PACKAGE}FILES+=	test_helpers.sh
${PACKAGE}FILES+=	capd_test_harness.sh
${PACKAGE}FILES+=	CapabilityKyuafile
${PACKAGE}FILES+=	run_authorityd_serviced_capability_tests.sh
${PACKAGE}FILESMODE_run_authorityd_serviced_capability_tests.sh=	0555

# ATF shell programs execute from the object directory before installation.
# Keep their shared harnesses beside them so raw object-tree test runs are as
# reliable as installed /usr/tests runs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/test_helpers.sh: ${.CURDIR}/test_helpers.sh
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/capd_test_harness.sh: \
    ${SRCTOP}/usr.sbin/authorityd/tests/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/test_helpers.sh ${.OBJDIR}/capd_test_harness.sh
CLEANFILES+=	test_helpers.sh capd_test_harness.sh
.endif

PROGS+=		capd_test_guardian
PROGS+=		capd_service_fixture
PROGS+=		capd_protocol_fixture
PROGS+=		service_probe
ATF_TESTS_C+=	activation_test
ATF_TESTS_C+=	domain_test
ATF_TESTS_C+=	on_demand_test
ATF_TESTS_C+=	fd_budget_test
ATF_TESTS_C+=	launch_limits_test
ATF_TESTS_C+=	manifest_compare_test
ATF_TESTS_C+=	management_enforce_test
ATF_TESTS_C+=	bundle_selection_test
ATF_TESTS_C+=	storage_lifecycle_test
ATF_TESTS_C+=	rc_ingest_test
ATF_TESTS_C+=	rc_adopt_test
ATF_TESTS_C+=	activation_calendar_test
BINDIR=		${TESTSDIR}

# rc_ingest.c is compiled into BOTH rc_ingest_test and rc_adopt_test.  A source
# shared by more than one test program is built once with the common CFLAGS —
# the per-program CFLAGS.<prog> do not reach a shared object — so the include
# paths rc_ingest.c needs (serviced_manifest.h in libcapbundle, which pulls in
# authorityrt.h from libauthorityrt) must be global.
CFLAGS+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt

# rc_ingest_test compiles the parser directly (pure logic, no daemon deps).
# rc_ingest.c comes from the serviced source dir via .PATH above; referencing
# it by basename keeps its object in the objdir (an absolute ${SRCTOP} path in
# SRCS would place the object inside $SRCTOP, which objdir builds forbid).
SRCS.rc_ingest_test=	rc_ingest_test.c rc_ingest.c
CFLAGS.rc_ingest_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.rc_ingest_test+=	-I${SRCTOP}/lib/libcapbundle

# rc_adopt_test compiles the adoption selection + unit-building logic directly
# (pure logic, no daemon event loop).  --gc-sections drops rc_adopt_register(),
# the only function that touches sd.services/svc_by_label, so the unit needs no
# daemon objects to link.  rc_adopt.c and rc_ingest.c come from the serviced
# source dir via the .PATH above; referencing them by basename keeps their
# objects in the objdir.
SRCS.rc_adopt_test=	rc_adopt_test.c rc_adopt.c rc_ingest.c
CFLAGS.rc_adopt_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.rc_adopt_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.rc_adopt_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.rc_adopt_test+=	-I${SRCTOP}/sys
CFLAGS.rc_adopt_test+=	-ffunction-sections -fdata-sections
LDFLAGS.rc_adopt_test+=	-Wl,--gc-sections

# activation_calendar_test compiles the pure calendar math directly (no daemon
# event loop or kqueue).  activation_calendar.c comes from the serviced source
# dir via the .PATH above; referencing it by basename keeps its object in the
# objdir.
SRCS.activation_calendar_test=	activation_calendar_test.c activation_calendar.c
CFLAGS.activation_calendar_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.activation_calendar_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.activation_calendar_test+=	-I${SRCTOP}/lib/libauthorityrt

CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.capd_protocol_fixture+=	-I${SRCTOP}/lib/libservice
LIBADD.capd_protocol_fixture+=	service channel capability

LIBADD.capd_service_fixture+=	capability channel service pthread
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libcapability
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libchannel
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libservice
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.capd_service_fixture+=	-I${SRCTOP}/sys

# service_probe: the ambient-reachability helper for service_reachability_test.
LIBADD.service_probe+=		service channel pthread
CFLAGS.service_probe+=		-I${SRCTOP}/lib/libservice
CFLAGS.service_probe+=		-I${SRCTOP}/lib/libchannel
CFLAGS.service_probe+=		-I${SRCTOP}/lib/libauthorityrt
CFLAGS.service_probe+=		-I${SRCTOP}/sys


# activation_test.c #includes ../activation.c inline; that now calls into the
# calendar math, so activation_calendar.c is linked alongside (by basename via
# .PATH).  --gc-sections drops the unreferenced daemon-state functions.
SRCS.activation_test=	activation_test.c activation_calendar.c
CFLAGS.activation_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.activation_test+=	-I${SRCTOP}/lib/libcapability
CFLAGS.activation_test+=	-I${SRCTOP}/sys
CFLAGS.activation_test+=	-ffunction-sections -fdata-sections
LDFLAGS.activation_test+=	-Wl,--gc-sections
LIBADD.activation_test+=	capbundle
CFLAGS.domain_test+=		-I${SRCTOP}/lib/libcapbundle
CFLAGS.domain_test+=		-I${SRCTOP}/lib/libchannel
CFLAGS.domain_test+=		-I${SRCTOP}/lib/libauthorityrt
CFLAGS.domain_test+=		-I${SRCTOP}/lib/libservice
CFLAGS.domain_test+=		-I${SRCTOP}/usr.sbin/serviced
CFLAGS.domain_test+=		-I${SRCTOP}/sys
CFLAGS.domain_test+=		-ffunction-sections -fdata-sections
LDFLAGS.domain_test+=		-Wl,--gc-sections
# domain.c/naming.c reach libchannel; the minted-channel case drives the
# serviced side from a helper thread and plays the client with libservice.
LIBADD.domain_test+=		channel service pthread
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libcapbundle
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libchannel
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libauthorityrt
CFLAGS.on_demand_test+=		-I${SRCTOP}/lib/libservice
CFLAGS.on_demand_test+=		-I${SRCTOP}/sys
CFLAGS.on_demand_test+=		-ffunction-sections -fdata-sections
LDFLAGS.on_demand_test+=	-Wl,--gc-sections
# The idle-shutdown cases pull supervisor.c + svc_proto.c into the unit, which
# reach libchannel and (in the mac_capability-gated case) a provider thread.
LIBADD.on_demand_test+=		channel pthread
CFLAGS.fd_budget_test+=	-I${SRCTOP}/sys
CFLAGS.launch_limits_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.launch_limits_test+=	-I${SRCTOP}/lib/libservice
CFLAGS.launch_limits_test+=	-I${SRCTOP}/sys
SRCS.manifest_compare_test=	manifest_compare_test.c manifest_compare.c
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.manifest_compare_test+=	-I${SRCTOP}/sys
# management_enforce_test compiles management.c directly (pure class logic, no
# daemon event loop).  management.c comes from the serviced source dir via the
# .PATH above; referencing it by basename keeps its object in the objdir.
SRCS.management_enforce_test=	management_enforce_test.c management.c
CFLAGS.management_enforce_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.management_enforce_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.management_enforce_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.management_enforce_test+=	-I${SRCTOP}/sys
SRCS.bundle_selection_test=	bundle_selection_test.c bundle_selection.c
CFLAGS.bundle_selection_test+=	-I${SRCTOP}/usr.sbin/serviced
SRCS.storage_lifecycle_test=	storage_lifecycle_test.c storage_lifecycle.c
CFLAGS.storage_lifecycle_test+=	-I${SRCTOP}/usr.sbin/serviced
CFLAGS.storage_lifecycle_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.storage_lifecycle_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.storage_lifecycle_test+=	-I${SRCTOP}/sys

.include <bsd.test.mk>
