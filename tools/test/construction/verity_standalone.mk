# SPDX-License-Identifier: BSD-2-Clause
# Included after stand/libsa/Makefile. Compile only; never link/install.
.PHONY: verity-standalone-core-compile
verity-standalone-core-compile:
	${CC} ${CFLAGS} -Werror -c ${SRCTOP}/sys/geom/verity/g_verity_verify.c -o ${.OBJDIR}/g_verity_verify.check.o
	${CC} ${CFLAGS} -Werror -c ${SRCTOP}/stand/libsa/verity_read.c -o ${.OBJDIR}/verity_read.check.o
	${CC} ${CFLAGS} -Werror -I${SRCTOP}/stand/common -c ${SRCTOP}/stand/common/veritydev.c -o ${.OBJDIR}/veritydev.check.o
	${CC} ${CFLAGS} -Werror -I${SRCTOP}/stand/common -c ${SRCTOP}/stand/common/verity_attach.c -o ${.OBJDIR}/verity_attach.check.o
