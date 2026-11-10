#
# Table-driven regression test of every system call that DescriptorQueue
# stage 0 rewired through the new per-descriptor operations (fo_pathconf,
# fo_statfs, fo_fsync, fo_setattr, fo_fadvise, fo_readdir,
# fo_copy_file_range, fo_acl, fo_extattr, fo_fcntl, fo_advlock), across
# every descriptor kind an unprivileged-or-root test can create.  Every
# expectation is FreeBSD's behaviour at the project base 3b9f9873d291,
# derived from that source and cited per cell; cells where the current
# tree differs are listed at the top of fdops_test.c with the ux-0 decision
# that restores them.
#
# None of the programs needs /dev/dq: they test the unattached path.
#
PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/dq_regress/fdops

ATF_TESTS_C+=	fdops_test

# The Linux-ABI half: a freestanding Linux program compiled at test time
# (clang --target=x86_64-linux-gnu), run under linux64.ko.
ATF_TESTS_SH+=	linux_fdops_test
${PACKAGE}FILES+=	linux_fdops.c
TEST_METADATA.linux_fdops_test+=	is_exclusive="true"

# Real Rocky Linux 9 binaries (test data staged under /compat/linux by
# stage-linux-compat.sh; skipped when absent).  Mounts fdescfs on /dev/fd.
ATF_TESTS_SH+=	linux_compat_test
TEST_METADATA.linux_compat_test+=	is_exclusive="true"

# mq_open(3) and mq_getfd_np(3) for the write-only message queue kind.
LIBADD.fdops_test+=	rt

# Mounts tmpfs and two fdescfs instances in the work directory, changes
# (and restores) the metadata of nodes under /dev through /dev/fd/N, and
# drops to an unprivileged uid in children: root, and alone.
TEST_METADATA.fdops_test+=	required_user="root"
TEST_METADATA.fdops_test+=	is_exclusive="true"
TEST_METADATA.fdops_test+=	timeout="900"

WARNS?=		6

.include <bsd.test.mk>
