PACKAGE=	tests

ATF_TESTS_SH+= firstboot_integrity_test
ATF_TESTS_SH+=  rc_subr_test safe_eval_test svcj_test
ATF_TESTS_SH+=  sysext_startup_test hostid_test root_integrity_test sshd_startup_test
ATF_TESTS_SH+=  syslogd_startup_test osrelease_startup_test motd_startup_test
ATF_TESTS_SH+=  ntpd_startup_test

# rc.subr routing pins (switchboard-init-rescope.md, slice SR0): plane-on and
# plane-off guests.  rc_pin_fixture is the test daemon's rc.d script; it must
# be installed root-owned and not group- or other-writable, as SwitchBoard
# requires of a routed script.
ATF_TESTS_SH+=	rc_routing_test
TEST_METADATA.rc_routing_test+=	is_exclusive="true"
PROGS+=		rc_pin_daemon rc_noroute_exec
LIBADD.rc_pin_daemon+=	util
BINDIR=		${TESTSDIR}
${PACKAGE}FILES+=	rc_pin_fixture
${PACKAGE}FILESMODE_rc_pin_fixture=	0555

# allow running this as part of the build - in DIRDEPS_BUILD at least
.if ${.MAKE.LEVEL} > 0 && ${MACHINE:Nhost*} == ""
SAFE_EVAL:= ${_PARSEDIR:U${.PARSEDIR:tA}:H}/safe_eval.sh
.export SAFE_EVAL
.endif

.include <bsd.test.mk>
