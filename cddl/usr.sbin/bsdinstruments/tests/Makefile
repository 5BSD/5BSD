.include <src.opts.mk>

PACKAGE=	bsdinstruments-tests

ATF_TESTS_SH=	bsdinstruments_test
ATF_TESTS_C=	bsdinstruments_unit_test

# The loader, renderer and filters, built into the unit test with the
# allocation functions wrapped for failure injection.
.PATH:		${.CURDIR:H}
SRCS.bsdinstruments_unit_test=	bsdinstruments_unit_test.c profile.c filter.c
CFLAGS.bsdinstruments_unit_test+=	-I${.CURDIR:H}
LDFLAGS.bsdinstruments_unit_test+=	-Wl,--wrap=malloc -Wl,--wrap=calloc \
				-Wl,--wrap=realloc -Wl,--wrap=strdup \
				-Wl,--wrap=strndup

# Scripted libdtrace, compiled and preloaded by the tests.
${PACKAGE}FILES+=	mockdtrace.c

.include <bsd.test.mk>
