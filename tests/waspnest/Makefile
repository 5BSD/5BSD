PACKAGE=	waspnest-tests
TESTSDIR=	${TESTSBASE}/waspnest
SCRIPTSDIR=	${TESTSDIR}

.PATH: ${SRCTOP}/docs

ATF_TESTS_SH+=	waspnest_package_test

SCRIPTS+=	waspnest-test.sh
SCRIPTSNAME_waspnest-test.sh=	waspnest-test
SCRIPTS+=	validate-nonvirtio-coverage.sh

${PACKAGE}FILES+=	README.md
${PACKAGE}FILES+=	waspnest-suite.tsv
${PACKAGE}FILES+=	waspnest-nonvirtio-coverage.tsv
${PACKAGE}FILES+=	waspnest-completion-matrix.md

# The shell tests resolve the runner and manifest through atf_get_srcdir().
# Copy the installed-file layout into a separate object directory so object
# tree and packaged Kyua runs exercise the same payload.
WASPNEST_OBJECT_FILES=	waspnest-test.sh \
			validate-nonvirtio-coverage.sh \
			waspnest-suite.tsv \
			waspnest-nonvirtio-coverage.tsv

.if ${.OBJDIR} != ${.CURDIR}
CLEANFILES+=	${WASPNEST_OBJECT_FILES}
beforedepend:	${WASPNEST_OBJECT_FILES}
.for _waspnest_object_file in ${WASPNEST_OBJECT_FILES}
${_waspnest_object_file}: ${.CURDIR}/${_waspnest_object_file}
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
.endfor
.endif

.include <bsd.test.mk>
