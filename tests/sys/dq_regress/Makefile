# Adversarial regression tests for existing behaviour on the paths the
# DescriptorQueue stages changed (real, unattached processes).  Each case's
# expectation is validated on a kernel from before stage 1c.

.include <src.opts.mk>

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/dq_regress

TESTS_SUBDIRS+=	fdops
TESTS_SUBDIRS+=	paths
TESTS_SUBDIRS+=	procnet

.include <bsd.test.mk>
