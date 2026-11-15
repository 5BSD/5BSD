PACKAGE=	mac-abac-tests
TESTSDIR=	${TESTSBASE}/sys/security/mac_abac

ATF_TESTS_SH+=	smoke_test
ATF_TESTS_C+=	parser_test
ATF_TESTS_C+=	kernel_test
ATF_TESTS_C+=	mprotect_test
ATF_TESTS_C+=	signal_context_test
ATF_TESTS_C+=	idle_pin_test
ATF_TESTS_C+=	idle_test

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

# mprotect_test switches the mode to enforcing, so it must not overlap other
# tests; its rules carry a subject label unique to the test process.
TEST_METADATA.mprotect_test+=	required_user="root"
TEST_METADATA.mprotect_test+=	required_kmods="mac_abac"
TEST_METADATA.mprotect_test+=	is_exclusive="true"

TEST_METADATA.signal_context_test+=	required_user="root"
TEST_METADATA.signal_context_test+=	required_kmods="mac_abac"
TEST_METADATA.signal_context_test+=	is_exclusive="true"

# idle_pin_test and idle_test switch the mode to enforcing; their rules name
# labels only their own workers and files carry.
TEST_METADATA.idle_pin_test+=	required_user="root"
TEST_METADATA.idle_pin_test+=	required_kmods="mac_abac"
TEST_METADATA.idle_pin_test+=	is_exclusive="true"
TEST_METADATA.idle_test+=	required_user="root"
TEST_METADATA.idle_test+=	required_kmods="mac_abac"
TEST_METADATA.idle_test+=	is_exclusive="true"
LIBADD.idle_test+=	pthread

.include <bsd.test.mk>
