PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/zfshandle
SCRIPTSDIR=	${TESTSDIR}

ATF_TESTS_C+=	zfshandle_rights_test
ATF_TESTS_C+=	zfshandle_derive_test
ATF_TESTS_C+=	zfshandle_pin_test
ATF_TESTS_C+=	zfshandle_phase2_test
ATF_TESTS_C+=	zfshandle_mount_test
ATF_TESTS_C+=	zfshandle_pool_test
ATF_TESTS_C+=	zfshandle_security_test
SCRIPTS+=	run_tests.sh
BINDIR=		${TESTSDIR}

CFLAGS.zfshandle_phase2_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_mount_test.c+=		-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_pool_test.c+=		-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.zfshandle_security_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
LIBADD.zfshandle_phase2_test+=		trustedzfs
LIBADD.zfshandle_mount_test+=		trustedzfs
LIBADD.zfshandle_pool_test+=		trustedzfs
LIBADD.zfshandle_security_test+=	trustedzfs

.include <bsd.test.mk>
