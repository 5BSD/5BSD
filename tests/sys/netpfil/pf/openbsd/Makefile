# 5BSD glue for the OpenBSD PF regress corpus in contrib/openbsd-pf.
# The corpus is installed beneath ${TESTSDIR}/srctree (tests/srctree.mk) so
# installed tests do not depend on the build machine's source tree.

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/netpfil/pf/openbsd

ATF_TESTS_SH+=	openbsd_regress
TEST_METADATA.openbsd_regress+=	execenv="jail" \
				required_user="root" \
				is_exclusive="true"

SRCTREE_FILES!=	cd ${SRCTOP} && find contrib/openbsd-pf -type f \
		    ! -name README.5BSD | sort

.include "${SRCTOP}/tests/srctree.mk"
.include <bsd.test.mk>
