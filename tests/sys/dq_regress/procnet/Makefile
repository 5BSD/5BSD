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
ATF_TESTS_C+=	procnet_control_test

# The Linux-ABI half of procnet_control_test: a freestanding Linux program
# compiled at test time (clang --target=x86_64-linux-gnu), run under
# linux64.ko.
ATF_TESTS_SH+=	linux_procctl_test
${PACKAGE}FILES+=	linux_procctl.c

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

# The process boundary today (dq-boundary design, part b0): the by-pid
# calls, terminals, job control, SIGIO, fork; named IPC; and the half that
# needs a queue and the capability plane (procnet_outside_test, which is
# the controller of the processes it attaches).
ATF_TESTS_C+=	procnet_boundary_test
ATF_TESTS_C+=	procnet_ipc_test
ATF_TESTS_C+=	procnet_outside_test
ATF_TESTS_SH+=	procnet_ipcs_test
PROGS+=		procnet_boundary_helper
SRCS.procnet_boundary_helper=	procnet_boundary_helper.c
MAN.procnet_boundary_helper=
BINDIR.procnet_boundary_helper=	${TESTSDIR}
LIBADD.procnet_boundary_test+=	pthread
LIBADD.procnet_ipc_test+=	rt
# The dq test support library's controller harness and queue access, as
# sources: tests/sys/dq/libdqtest's archive is built in another directory
# that is not ordered before this one.
.PATH:		${SRCTOP}/tests/sys/dq/libdqtest
SRCS.procnet_outside_test=	procnet_outside_test.c dqt_access.c \
				dqt_harness.c
CFLAGS.procnet_outside_test.c+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libdq \
		-I${SRCTOP}/tests/sys/dq/libdqtest \
		-I${SRCTOP}/sys/dev/mac_capability \
		-I${SRCTOP}/tests/sys/mac_capability
CFLAGS.dqt_access.c+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libdq \
		-I${SRCTOP}/usr.sbin/capsule
CFLAGS.dqt_harness.c+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libdq
LIBADD.procnet_outside_test+=	dq pthread util

# The Linux-ABI half: a freestanding static Linux program (no Linux libc)
# compiled at test time (clang --target=x86_64-linux-gnu), run under
# linux64.ko; the .exp files are the rows it printed when recorded.
ATF_TESTS_SH+=	linux_boundary_test
${PACKAGE}FILES+=	linux_boundary.c
${PACKAGE}FILES+=	linux_boundary_main.exp
${PACKAGE}FILES+=	linux_boundary_attached.exp

LIBADD.procnet_exec_test+=	pthread
LIBADD.procnet_jail_test+=	jail pthread
LIBADD.procnet_socket_test+=	jail
LIBADD.procnet_unix_test+=	pthread
LIBADD.procnet_control_test+=	pthread

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
# Jails and security.bsd.unprivileged_proc_debug; System V ids and
# listings of the whole system; shields and a controller.
TEST_METADATA.procnet_boundary_test+=	is_exclusive="true"
TEST_METADATA.procnet_ipc_test+=	is_exclusive="true"
TEST_METADATA.procnet_outside_test+=	is_exclusive="true"
TEST_METADATA.procnet_ipcs_test+=	is_exclusive="true" required_user="root"
TEST_METADATA.linux_boundary_test+=	is_exclusive="true" required_user="root"
TEST_METADATA.procnet_socket_test+=	is_exclusive="true"

WARNS?=		6

.include <bsd.test.mk>
