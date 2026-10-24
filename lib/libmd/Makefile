SHLIBDIR?= /lib

.include <src.opts.mk>
.include <bsd.compiler.mk>

PACKAGE=	runtime
LIB=	md
SHLIB_MAJOR= 7
SRCS=	md4c.c md5c.c md4hl.c md5hl.c \
	rmd160c.c rmd160hl.c \
	sha0c.c sha0hl.c sha1c.c sha1hl.c \
	sha224hl.c sha256c.c sha256hl.c \
	sha384hl.c \
	sha512c.c sha512hl.c sha512t224hl.c sha512t256hl.c \
	skein.c skein_block.c \
	skein256hl.c skein512hl.c skein1024hl.c
INCS=	md4.h md5.h ripemd.h sha.h sha224.h sha256.h sha384.h sha512.h \
	sha512t.h skein.h skein_port.h skein_freebsd.h skein_iv.h

WARNS?=	0

VERSION_DEF=	${SRCTOP}/lib/libc/Versions.def
SYMBOL_MAPS=	${.CURDIR}/Symbol.map

MAN+=	md4.3 md5.3 ripemd.3 sha.3 sha256.3 sha512.3 skein.3
MLINKS+=md4.3 MD4Init.3 md4.3 MD4Update.3 md4.3 MD4Final.3
MLINKS+=md4.3 MD4End.3  md4.3 MD4File.3   md4.3 MD4FileChunk.3
MLINKS+=md4.3 MD4Data.3
MLINKS+=md5.3 MD5Init.3 md5.3 MD5Update.3 md5.3 MD5Final.3
MLINKS+=md5.3 MD5End.3  md5.3 MD5File.3   md5.3 MD5FileChunk.3
MLINKS+=md5.3 MD5Data.3
MLINKS+=ripemd.3 RIPEMD160_Init.3  ripemd.3 RIPEMD160_Update.3
MLINKS+=ripemd.3 RIPEMD160_Final.3 ripemd.3 RIPEMD160_Data.3
MLINKS+=ripemd.3 RIPEMD160_End.3   ripemd.3 RIPEMD160_File.3
MLINKS+=ripemd.3 RIPEMD160_FileChunk.3
MLINKS+=sha.3 SHA_Init.3  sha.3 SHA_Update.3  sha.3 SHA_Final.3
MLINKS+=sha.3 SHA_End.3   sha.3 SHA_File.3    sha.3 SHA_FileChunk.3
MLINKS+=sha.3 SHA_Data.3
MLINKS+=sha.3 SHA1_Init.3 sha.3 SHA1_Update.3 sha.3 SHA1_Final.3
MLINKS+=sha.3 SHA1_End.3  sha.3 SHA1_File.3   sha.3 SHA1_FileChunk.3
MLINKS+=sha.3 SHA1_Data.3
MLINKS+=sha256.3 SHA224_Init.3  sha256.3 SHA224_Update.3
MLINKS+=sha256.3 SHA224_Final.3 sha256.3 SHA224_End.3
MLINKS+=sha256.3 SHA224_File.3  sha256.3 SHA224_FileChunk.3
MLINKS+=sha256.3 SHA224_Data.3
MLINKS+=sha256.3 SHA256_Init.3  sha256.3 SHA256_Update.3
MLINKS+=sha256.3 SHA256_Final.3 sha256.3 SHA256_End.3
MLINKS+=sha256.3 SHA256_File.3  sha256.3 SHA256_FileChunk.3
MLINKS+=sha256.3 SHA256_Data.3
MLINKS+=sha512.3 SHA384_Init.3  sha512.3 SHA384_Update.3
MLINKS+=sha512.3 SHA384_Final.3 sha512.3 SHA384_End.3
MLINKS+=sha512.3 SHA384_File.3  sha512.3 SHA384_FileChunk.3
MLINKS+=sha512.3 SHA384_Data.3  sha512.3 sha384.3
MLINKS+=sha512.3 SHA512_Init.3  sha512.3 SHA512_Update.3
MLINKS+=sha512.3 SHA512_Final.3 sha512.3 SHA512_End.3
MLINKS+=sha512.3 SHA512_File.3  sha512.3 SHA512_FileChunk.3
MLINKS+=sha512.3 SHA512_Data.3
MLINKS+=sha512.3 SHA512_224_Init.3  sha512.3 SHA512_224_Update.3
MLINKS+=sha512.3 SHA512_224_Final.3 sha512.3 SHA512_224_End.3
MLINKS+=sha512.3 SHA512_224_File.3  sha512.3 SHA512_224_FileChunk.3
MLINKS+=sha512.3 SHA512_224_Data.3
MLINKS+=sha512.3 SHA512_256_Init.3  sha512.3 SHA512_256_Update.3
MLINKS+=sha512.3 SHA512_256_Final.3 sha512.3 SHA512_256_End.3
MLINKS+=sha512.3 SHA512_256_File.3  sha512.3 SHA512_256_FileChunk.3
MLINKS+=sha512.3 SHA512_256_Data.3
MLINKS+=skein.3 SKEIN256_Init.3  skein.3 SKEIN256_Update.3
MLINKS+=skein.3 SKEIN256_Final.3 skein.3 SKEIN256_End.3
MLINKS+=skein.3 SKEIN256_File.3  skein.3 SKEIN256_FileChunk.3
MLINKS+=skein.3 SKEIN256_Data.3  skein.3 skein256.3
MLINKS+=skein.3 SKEIN512_Init.3  skein.3 SKEIN512_Update.3
MLINKS+=skein.3 SKEIN512_Final.3 skein.3 SKEIN512_End.3
MLINKS+=skein.3 SKEIN512_File.3  skein.3 SKEIN512_FileChunk.3
MLINKS+=skein.3 SKEIN512_Data.3  skein.3 skein512.3
MLINKS+=skein.3 SKEIN1024_Init.3  skein.3 SKEIN1024_Update.3
MLINKS+=skein.3 SKEIN1024_Final.3 skein.3 SKEIN1024_End.3
MLINKS+=skein.3 SKEIN1024_File.3  skein.3 SKEIN1024_FileChunk.3
MLINKS+=skein.3 SKEIN1024_Data.3  skein.3 skein1024.3

CLEANFILES+=	md[245]hl.c md[245].ref md[245].3 mddriver \
		rmd160.ref rmd160hl.c rmddriver \
		sha0.ref sha0hl.c sha1.ref sha1hl.c shadriver \
		sha224.ref sha256.ref sha224hl.c sha256hl.c \
		sha384hl.c sha384.ref \
		sha512.ref sha512hl.c \
		sha512t224.ref sha512t224hl.c \
		sha512t256.ref sha512t256hl.c \
		skein256hl.c skein512hl.c skein1024hl.c \
		skein256.ref skein512.ref skein1024.ref \
		skeindriver

# Need src tree sys/md5.h for MD5FileChunk prototype on older systems.
SRCS+=		sys/md5.h
CLEANDIRS=	sys
CFLAGS+=	-I.
sys/md5.h: ${SRCTOP}/sys/${.TARGET} .NOMETA
	ln -sf ${.ALLSRC} ${.TARGET}

# Define WEAK_REFS to provide weak aliases for libmd symbols
#
# Note that the same sources are also used internally by libcrypt,
# in which case:
#   * macros are used to rename symbols to libcrypt internal names
#   * no weak aliases are generated
CFLAGS+= -I${.CURDIR} -I${SRCTOP}/sys/crypto/sha2
CFLAGS+= -I${SRCTOP}/sys/crypto/skein
CFLAGS+= -DWEAK_REFS
# unroll the 256 and 512 loops, half unroll the 1024
CFLAGS.skein_block.c+= -DSKEIN_LOOP=995
.PATH: ${.CURDIR}/${MACHINE_ARCH} ${SRCTOP}/sys/crypto/sha2
.PATH: ${SRCTOP}/sys/crypto/skein ${SRCTOP}/sys/crypto/skein/${MACHINE_ARCH}
.PATH: ${SRCTOP}/sys/crypto

USE_ASM_SOURCES?=1
.if defined(BOOTSTRAPPING) || ${MK_MACHDEP_OPTIMIZATIONS} == no
# Don't build ASM sources when bootstrapping to avoid toolchain dependencies
USE_ASM_SOURCES:=0
.endif

.if ${USE_ASM_SOURCES} != 0
.if exists(${MACHINE_ARCH}/md5block.S)
SRCS+=	md5block.S
CFLAGS+= -DMD5_ASM
.if exists(${MACHINE_ARCH}/md5dispatch.c)
SRCS+=  md5dispatch.c
.endif
.endif
.if exists(${MACHINE_ARCH}/sha1block.S)
SRCS+=	sha1block.S
CFLAGS+= -DSHA1_ASM
.if exists(${MACHINE_ARCH}/sha1dispatch.c)
SRCS+=  sha1dispatch.c
.endif
.endif
.if exists(${MACHINE_ARCH}/rmd160.S)
SRCS+=	rmd160.S
CFLAGS+= -DRMD160_ASM
.endif
.if exists(${MACHINE_ARCH}/skein_block_asm.S)
# Fully unroll all loops in the assembly optimized version
ACFLAGS+= -DSKEIN_LOOP=0
SRCS+= skein_block_asm.S
CFLAGS+= -DSKEIN_ASM -DSKEIN_USE_ASM=1792 # list of block functions to replace with assembly: 256+512+1024 = 1792
# 20201002 Add explict Makefile dependency for r366344 (reenabled assembly
# optimized version). SKEIN_USE_ASM determines which routines should come from
# the assembly vs C versions, and skein_block needs to be rebuilt if it changes.
skein_block.o skein_block.pico: Makefile
.endif
.if exists(${MACHINE_ARCH}/rmd160.S) || exists(${MACHINE_ARCH}/skein_block_asm.S)
ACFLAGS+= -DELF -Wa,--noexecstack
.endif
.if ${MACHINE_CPUARCH} == "aarch64"
SRCS+=	sha256c_arm64.c
CFLAGS+= -DARM64_SHA2
CFLAGS.sha256c_arm64.c+= -march=armv8-a+crypto
.if ${COMPILER_FEATURES:Maarch64-sha512}
SRCS+=	sha512c_arm64.c
CFLAGS+= -DARM64_SHA512
CFLAGS.sha512c_arm64.c+= -march=armv8.2-a+sha3
.endif # aarch64-sha512
.endif
.endif # ${USE_ASM_SOURCES} != 0

# Generator parameters are shared build metadata; scripts contain the transformations.
# Single executable inputs; unlike RM these variables never contain flags.
LIBMD_GEN_SED?= sed
LIBMD_GEN_CAT?= cat
LIBMD_GEN_MV?= mv
LIBMD_GEN_RM?= rm

LIBMD_GENHL_ARGS.md4hl.c= 16 md4 MD4 -
LIBMD_GENHL_ARGS.md5hl.c= 16 md5 MD5 -
LIBMD_GENHL_ARGS.sha0hl.c= 20 sha SHA_ -
LIBMD_GENHL_ARGS.sha1hl.c= 20 sha SHA1_ -
LIBMD_GENHL_ARGS.sha224hl.c= 28 sha224 SHA224_ -
LIBMD_GENHL_ARGS.sha256hl.c= 32 sha256 SHA256_ -
LIBMD_GENHL_ARGS.sha384hl.c= 48 sha384 SHA384_ -
LIBMD_GENHL_ARGS.sha512hl.c= 64 sha512 SHA512_ -
LIBMD_GENHL_ARGS.sha512t224hl.c= 28 sha512t SHA512_224_ SHA512_CTX
LIBMD_GENHL_ARGS.sha512t256hl.c= 32 sha512t SHA512_256_ SHA512_CTX
LIBMD_GENHL_ARGS.rmd160hl.c= 20 ripemd RIPEMD160_ -
LIBMD_GENHL_ARGS.skein256hl.c= 32 skein SKEIN256_ -
LIBMD_GENHL_ARGS.skein512hl.c= 64 skein SKEIN512_ -
LIBMD_GENHL_ARGS.skein1024hl.c= 128 skein SKEIN1024_ -

LIBMD_GENHL_SRCS= ${SRCS:M*hl.c}
.for _src in ${LIBMD_GENHL_SRCS}
${_src}: ${.CURDIR}/mdXhl.c ${.CURDIR}/genhl.sh
	${SH:Ush} ${.CURDIR}/genhl.sh ${LIBMD_GENHL_ARGS.${_src}} \
	    ${.CURDIR}/mdXhl.c ${.TARGET} ${LIBMD_GEN_SED:Q} ${LIBMD_GEN_MV:Q} ${LIBMD_GEN_RM:Q}
.endfor

.for i in 2 4 5
LIBMD_GENMAN_ARGS.md${i}.3= md${i} MD${i}
md${i}.3: ${.CURDIR}/mdX.3 ${.CURDIR}/md${i}.copyright ${.CURDIR}/genman.sh
	${SH:Ush} ${.CURDIR}/genman.sh ${LIBMD_GENMAN_ARGS.md${i}.3} \
	    ${.CURDIR}/mdX.3 ${.CURDIR}/md${i}.copyright ${.TARGET} ${LIBMD_GEN_SED:Q} ${LIBMD_GEN_CAT:Q} ${LIBMD_GEN_MV:Q} ${LIBMD_GEN_RM:Q}
.endfor

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
