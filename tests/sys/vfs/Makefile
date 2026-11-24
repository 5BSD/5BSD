PACKAGE=	tests

TESTSDIR=		${TESTSBASE}/sys/vfs

ATF_TESTS_C+=	lookup_cap_dotdot
ATF_TESTS_C+=	lookup_cap_dotdot_mount
ATF_TESTS_C+=	ufs_suspend_atime
TEST_METADATA.ufs_suspend_atime+=	is_exclusive="true"
LIBADD.ufs_suspend_atime+=	pthread
ATF_TESTS_C+=	ufs_quota_lock_order
TEST_METADATA.ufs_quota_lock_order+=	is_exclusive="true"
CFLAGS.lookup_cap_dotdot.c+=	-I${SRCTOP}/tests

ATF_TESTS_SH+=	abi_root_symlink

#ATF_TESTS_SH+=	lookup_test

TAP_TESTS_SH+=	trailing_slash

.include <bsd.test.mk>
