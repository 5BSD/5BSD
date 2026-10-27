#

.PATH: ${LIBC_SRCTOP}/csu
.include "${LIBC_SRCTOP}/csu/${LIBC_ARCH}/Makefile.inc"

SRCS+= \
	 libc_start1.c

CFLAGS+= -I${LIBC_SRCTOP}/csu/${LIBC_ARCH}
SYM_MAPS+=${LIBC_SRCTOP}/csu/Symbol.map

.if !empty(CFLAGS:M-DCRT_IRELOC_REL*)
TEXTUAL_SRCS.libc_start1.c= ${LIBC_SRCTOP}/csu/${LIBC_ARCH}/reloc.c
.endif
