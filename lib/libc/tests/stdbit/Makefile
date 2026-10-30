TESTSDIR=	${TESTSBASE}/lib/libc/stdbit

# ensure libc functions are tested, not clang's builtins
CFLAGS+=	-fno-builtin

ATF_TESTS_C+=	stdc_bit_ceil_test \
		stdc_bit_floor_test \
		stdc_bit_width_test \
		stdc_count_ones_test \
		stdc_count_zeros_test \
		stdc_first_leading_one_test \
		stdc_first_leading_zero_test \
		stdc_first_trailing_one_test \
		stdc_first_trailing_zero_test \
		stdc_has_single_bit_test \
		stdc_leading_ones_test \
		stdc_leading_zeros_test \
		stdc_trailing_ones_test \
		stdc_trailing_zeros_test

# Each test includes the framework, which includes the kernel for each type.
.for _test in ${ATF_TESTS_C}
TEXTUAL_SRCS.${_test}.c= ${.CURDIR}/stdbit-test-framework.c \
    ${.CURDIR}/stdbit-test-kernel.c
.endfor

.include <bsd.test.mk>

.for _src in ${SRCS}
.if defined(TEXTUAL_SRCS.${_src})
${_src:R}.o ${_src:R}.pieo: ${TEXTUAL_SRCS.${_src}}
.endif
.endfor
