#
# Adversarial regression tests of the path system calls for processes not
# attached to a DescriptorQueue controller.  Every expectation is the
# behaviour of the kernel from before stage 1c (3f330ee172d); see the
# comment at the top of paths_common.h.
#
PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/dq_regress/paths

ATF_TESTS_C+=	paths_shape_test
ATF_TESTS_C+=	paths_open_test
ATF_TESTS_C+=	paths_at_test
ATF_TESTS_C+=	paths_ns_test
ATF_TESTS_C+=	paths_attr_test
ATF_TESTS_C+=	paths_cap_test
ATF_TESTS_C+=	paths_race_test
ATF_TESTS_C+=	paths_fast_test
ATF_TESTS_C+=	paths_union_test

.for _t in ${ATF_TESTS_C}
SRCS.${_t}=	${_t}.c paths_common.c
.endfor

LIBADD.paths_race_test+=	pthread
LIBADD.paths_union_test+=	util

# Sets vfs.lookup_cap_dotdot (restored): run alone.
TEST_METADATA.paths_cap_test+=	is_exclusive="true"
# Counts lockless lookups with dtrace: run alone.
TEST_METADATA.paths_fast_test+=	is_exclusive="true"
TEST_METADATA.paths_race_test+=	timeout="600"

# The burst of lookups paths_fast_test traces under dtrace -c.
PROGS+=		paths_statburst
SRCS.paths_statburst=	paths_statburst.c
MAN.paths_statburst=
BINDIR.paths_statburst=	${TESTSDIR}

WARNS?=		6

.include <bsd.test.mk>
