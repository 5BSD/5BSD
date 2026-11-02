ATF_TESTS_SH+= firstboot_integrity_test
ATF_TESTS_SH+=  rc_subr_test safe_eval_test svcj_test
ATF_TESTS_SH+=  sysext_startup_test hostid_test root_integrity_test sshd_startup_test
ATF_TESTS_SH+=  syslogd_startup_test osrelease_startup_test motd_startup_test
ATF_TESTS_SH+=  ntpd_startup_test

# allow running this as part of the build - in DIRDEPS_BUILD at least
.if ${.MAKE.LEVEL} > 0 && ${MACHINE:Nhost*} == ""
SAFE_EVAL:= ${_PARSEDIR:U${.PARSEDIR:tA}:H}/safe_eval.sh
.export SAFE_EVAL
.endif

.include <bsd.test.mk>
