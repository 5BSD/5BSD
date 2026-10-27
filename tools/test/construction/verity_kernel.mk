# SPDX-License-Identifier: BSD-2-Clause
# Included after a configured kernel Makefile. Compile only; never link/install.
.PHONY: verity-core-compile
verity-core-compile:
	${CC} ${CFLAGS} -Werror -c ${S}/geom/verity/g_verity_verify.c -o g_verity_verify.check.o
	${CC} ${CFLAGS} -Werror -c ${S}/geom/verity/g_verity_io.c -o g_verity_io.check.o
	${CC} ${CFLAGS} -Werror -c ${S}/geom/verity/g_verity_provider.c -o g_verity_provider.check.o
	${CC} ${CFLAGS} -Werror -c ${S}/geom/verity/g_verity_boot.c -o g_verity_boot.check.o
	${CC} ${CFLAGS} -Werror -c ${S}/geom/verity/g_verity_mount.c -o g_verity_mount.check.o
	${CC} ${CFLAGS} -Werror -DGEOM_VERITY -c ${S}/kern/vfs_mountroot.c -o vfs_mountroot.verity.check.o

.PHONY: verity-crypto-compile
verity-crypto-compile:
	${CC} ${CFLAGS} -Werror -c ${S}/../tools/test/construction/verity_crypto/verity_crypto_test.c -o verity_crypto_test.check.o
