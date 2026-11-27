PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/usr.sbin/praudit

ATF_TESTS_SH=	praudit_test

${PACKAGE}FILES+=			\
		input/trail 		\
		input/corrupted		\
		input/del_comma 	\
		input/del_underscore 	\
		input/no_args 		\
		input/numeric_form 	\
		input/raw_form 		\
		input/same_line 	\
		input/short_form 	\
		input/xml_form		\
		input/golden_tokens	\
		input/golden_numeric	\
		input/golden_raw	\
		input/golden_short	\
		input/golden_oneline	\
		input/golden_xml	\
		input/procident_trail	\
		input/procident_old_numeric \
		input/procident_old_raw	\
		input/procident_old_xml	\
		input/procident_new_numeric \
		input/procident_new_raw	\
		input/procident_new_xml	\
		input/rights_trail	\
		input/rights_numeric

TEST_METADATA+= timeout="10"

.include <bsd.test.mk>
