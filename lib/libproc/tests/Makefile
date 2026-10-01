ATF_TESTS_C+=	proc_test

PROGS=		target_prog target_prog_static
SRCS_target_prog=	target_prog.c
BINDIR_target_prog=	${TESTSDIR}
SRCS_target_prog_static=	target_prog.c
BINDIR_target_prog_static=	${TESTSDIR}
NO_SHARED.target_prog_static=	yes

LIBADD=	elf proc rtld_db util pthread

# Ensure that symbols aren't stripped from the test program, as they're needed
# for testing symbol lookup.
STRIP=
CFLAGS.target_prog.c+= -O0

.include <bsd.test.mk>
