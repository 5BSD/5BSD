PACKAGE=	tzfs-tests
TESTSDIR=	${TESTSBASE}/sys/zfshandle
SCRIPTSDIR=	${TESTSDIR}

# The shared helper includes <sys/zfshandle.h>; needed for standalone builds
# (in a full world build it resolves from the staged headers).
CFLAGS+=	-I${SRCTOP}/sys

ATF_TESTS_C+=	zfshandle_rights_test
ATF_TESTS_C+=	zfshandle_derive_test
ATF_TESTS_C+=	zfshandle_pin_test
ATF_TESTS_C+=	zfshandle_phase2_test
ATF_TESTS_C+=	zfshandle_mount_test
ATF_TESTS_C+=	zfshandle_pool_test
ATF_TESTS_C+=	zfshandle_security_test
ATF_TESTS_C+=	zfshandle_verbs_test
ATF_TESTS_C+=	zfshandle_negative_test
ATF_TESTS_C+=	zfshandle_hardening_test
SCRIPTS+=	run_tests.sh
BINDIR=		${TESTSDIR}

CFLAGS.zfshandle_phase2_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_mount_test.c+=		-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_pool_test.c+=		-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_security_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_verbs_test.c+=		-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_negative_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_hardening_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
LIBADD.zfshandle_phase2_test+=		trustedzfs
LIBADD.zfshandle_mount_test+=		trustedzfs
LIBADD.zfshandle_pool_test+=		trustedzfs
LIBADD.zfshandle_security_test+=	trustedzfs
LIBADD.zfshandle_verbs_test+=		trustedzfs
LIBADD.zfshandle_negative_test+=	trustedzfs
LIBADD.zfshandle_hardening_test+=	trustedzfs
LIBADD.zfshandle_rights_test+=	util

.include <bsd.test.mk>
