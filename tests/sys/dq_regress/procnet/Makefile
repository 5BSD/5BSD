#
# Adversarial regression tests: processes, credentials, jails, core dumps,
# sockets and administrative calls of processes NOT attached to a dq(4)
# controller.  Every expectation is the behaviour of the kernel before
# DescriptorQueue stage 1c (commit 3f330ee172d), except the documented
# socket(2) errno order (D139/D155), which the socket cases assert in its
# new form unless run with "-v pre1c=yes" (see procnet_common.h).
#
# None of the programs needs /dev/dq: they test the unattached path.
#
PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/dq_regress/procnet

ATF_TESTS_C+=	procnet_exec_test
ATF_TESTS_C+=	procnet_cred_test
ATF_TESTS_C+=	procnet_jail_test
ATF_TESTS_C+=	procnet_core_test
ATF_TESTS_C+=	procnet_socket_test
ATF_TESTS_C+=	procnet_unix_test
ATF_TESTS_C+=	procnet_admin_test
ATF_TESTS_C+=	procnet_syscall_test
ATF_TESTS_C+=	procnet_audit_test

# The image the exec, core and syscall cases run: dynamic, and a static
# copy (no PT_INTERP).
PROGS+=		procnet_helper
SRCS.procnet_helper=	procnet_helper.c
MAN.procnet_helper=
BINDIR.procnet_helper=	${TESTSDIR}
PROGS+=		procnet_helper_static
SRCS.procnet_helper_static=	procnet_helper_static.c
NO_SHARED.procnet_helper_static=	yes
MAN.procnet_helper_static=
BINDIR.procnet_helper_static=	${TESTSDIR}

LIBADD.procnet_exec_test+=	pthread
LIBADD.procnet_jail_test+=	jail pthread
LIBADD.procnet_socket_test+=	jail
LIBADD.procnet_unix_test+=	pthread

# The audit cases share the audit suite's auditpipe harness.
.PATH:		${SRCTOP}/tests/sys/audit
SRCS.procnet_audit_test=	procnet_audit_test.c utils.c
CFLAGS+=	-I${SRCTOP}/tests/sys/audit -I${SRCTOP}/contrib/openbsm
LIBADD.procnet_audit_test+=	bsm util
LDADD.procnet_audit_test+=	${LIBAUDITD}
# As tests/sys/audit: libprivateauditd.a is not PIE.
MK_PIE:=	no

# Everything here creates set-id files, jails, mounts, md(4) units, swap,
# or changes credentials: root.  Cases test the unprivileged side by
# dropping to an unused uid in a child.
.for _t in ${ATF_TESTS_C}
TEST_METADATA.${_t}+=	required_user="root"
.endfor
# Changes kern.corefile and kern.sugid_coredump.
TEST_METADATA.procnet_core_test+=	is_exclusive="true"
# Mounts, swap, acct(2) and ktrace(2) of the whole system: run alone.
TEST_METADATA.procnet_admin_test+=	is_exclusive="true"
# One auditing process at a time (tests/sys/audit).
TEST_METADATA.procnet_audit_test+=	is_exclusive="true" timeout="60"
TEST_METADATA.procnet_audit_test+=	required_files="/etc/rc.d/auditd /dev/auditpipe"
# Creates jails.
TEST_METADATA.procnet_jail_test+=	is_exclusive="true"
TEST_METADATA.procnet_socket_test+=	is_exclusive="true"

WARNS?=		6

.include <bsd.test.mk>
