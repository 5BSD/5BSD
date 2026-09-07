PACKAGE=	authorityd-tests

.PATH:	${SRCTOP}/usr.sbin/authorityd/tests

ATF_TESTS_SH+=	authorityd_test
ATF_TESTS_SH+=	authorityd_init_test
ATF_TESTS_SH+=	authorityd_lifecycle_test
ATF_TESTS_SH+=	authorityd_bootstrap_test
ATF_TESTS_SH+=	capd_test_guardian_test
ATF_TESTS_SH+=	capsule_boot_test

PROGS+=		capd_test_guardian
PROGS+=		capd_bootstrap_fixture
BINDIR=		${TESTSDIR}

CFLAGS.capd_bootstrap_fixture+=	-I${SRCTOP}/sys
CFLAGS.capd_bootstrap_fixture+=	-I${SRCTOP}/lib/libauthorityrt

${PACKAGE}FILES+=	capd_test_harness.sh bsdinstall-config.sh \
                run_capsule_vm_boot_test.sh \
			run_capsule_vm_image_test.sh
${PACKAGE}FILESMODE_run_capsule_vm_boot_test.sh=	0555
${PACKAGE}FILESMODE_run_capsule_vm_image_test.sh=	0555

# Keep the shared harness beside generated ATF programs for object-tree runs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/capd_test_harness.sh: ${.CURDIR}/capd_test_harness.sh
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/bsdinstall-config.sh: ${SRCTOP}/usr.sbin/bsdinstall/scripts/config
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/run_capsule_vm_boot_test.sh: ${.CURDIR}/run_capsule_vm_boot_test.sh
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/run_capsule_vm_image_test.sh: ${.CURDIR}/run_capsule_vm_image_test.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/capd_test_harness.sh ${.OBJDIR}/bsdinstall-config.sh \
	${.OBJDIR}/run_capsule_vm_boot_test.sh \
	${.OBJDIR}/run_capsule_vm_image_test.sh
CLEANFILES+=	capd_test_harness.sh bsdinstall-config.sh \
		run_capsule_vm_boot_test.sh run_capsule_vm_image_test.sh
.endif

ATF_TESTS_C+=	req_validate_test
CFLAGS.req_validate_test+=	-I${SRCTOP}/sys
CFLAGS.req_validate_test+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS.req_validate_test+=	-I${SRCTOP}/lib/libcapbundle
CFLAGS.req_validate_test+=	-I${SRCTOP}/usr.sbin/authorityd

# Capsule PID-1 unit tests exercise the pure decision/hygiene helpers factored
# out of capsule.c (capsule_ambient.h, capsule_lifecycle.h, capsule_plane.h) —
# header-only, no PID-1 state machine or daemon objects linked.
ATF_TESTS_C+=	capsule_ambient_test
CFLAGS.capsule_ambient_test+=	-I${SRCTOP}/usr.sbin/authorityd

ATF_TESTS_C+=	capsule_lifecycle_test
CFLAGS.capsule_lifecycle_test+=	-I${SRCTOP}/usr.sbin/authorityd
CFLAGS.capsule_lifecycle_test+=	-I${SRCTOP}/lib/libauthorityrt

ATF_TESTS_C+=	capsule_plane_test
CFLAGS.capsule_plane_test+=	-I${SRCTOP}/usr.sbin/authorityd

.include <bsd.test.mk>
