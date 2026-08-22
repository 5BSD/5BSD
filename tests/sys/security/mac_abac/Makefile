PACKAGE=	mac-abac-tests
TESTSDIR=	${TESTSBASE}/sys/security/mac_abac

ATF_TESTS_SH+=	smoke_test
ATF_TESTS_C+=	parser_test
ATF_TESTS_C+=	kernel_test

SRCS.parser_test=	parser_test.c parse_line.c
.PATH: ${SRCTOP}/usr.sbin/mac_abacd

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/usr.sbin/mac_abacd

TEST_METADATA.smoke_test+=	required_user="root"
TEST_METADATA.smoke_test+=	required_kmods="mac_abac"
TEST_METADATA.smoke_test+=	is_exclusive="true"
TEST_METADATA.kernel_test+=	required_user="root"
TEST_METADATA.kernel_test+=	required_kmods="mac_abac"
TEST_METADATA.kernel_test+=	is_exclusive="true"

.include <bsd.test.mk>
