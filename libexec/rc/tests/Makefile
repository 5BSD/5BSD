ATF_TESTS_SH+=  rc_subr_test safe_eval_test
ATF_TESTS_SH+=  sysext_startup_test
ATF_TESTS_SH_SED_sysext_startup_test+= -e 's,@SRCTOP@,${SRCTOP},g'

# allow running this as part of the build - in DIRDEPS_BUILD at least
.if ${.MAKE.LEVEL} > 0 && ${MACHINE:Nhost*} == ""
SAFE_EVAL:= ${_PARSEDIR:U${.PARSEDIR:tA}:H}/safe_eval.sh
.export SAFE_EVAL
.endif

.include <bsd.test.mk>
