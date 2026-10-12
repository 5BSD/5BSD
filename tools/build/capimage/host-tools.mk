# SPDX-License-Identifier: BSD-2-Clause
# Native tools for signing a cross-built stage. Invoke from a new /usr/obj
# directory with -f /usr/src/tools/build/capimage/host-tools.mk.
SRCTOP?= /usr/src
CC?= cc
CFLAGS+= -O2 -Wall -Wextra -Werror
CFLAGS+= -I${.OBJDIR} -I${SRCTOP}/lib/libcapimage
CFLAGS+= -I${SRCTOP}/lib/libcapbundle -I${SRCTOP}/lib/libcapsulert
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
# Host ABI headers take precedence; source-only capability definitions remain
# available for parsing manifests. Never use target syscall/libc headers here.
CFLAGS+= -iquote${SRCTOP}/sys -idirafter ${SRCTOP}/sys
.PATH: ${SRCTOP}/usr.sbin/capsign ${SRCTOP}/usr.sbin/elfcache
.PATH: ${SRCTOP}/lib/libcapimage ${SRCTOP}/lib/libcapbundle ${SRCTOP}/lib/libcapsulert
COMMON= capimage.o
BUNDLE= libcapbundle.o libcapbundle_parse.o libcapbundle_verify.o libcapbundle_sign.o claim_parse.o
all: capsign elfcache
sys/capimage.h: ${SRCTOP}/sys/sys/capimage.h
	mkdir -p sys
	cp ${.ALLSRC} ${.TARGET}
capsign.o capsign_tree.o elfcache.o ${COMMON} ${BUNDLE}: sys/capimage.h
.c.o:
	${CC} ${CFLAGS} -c ${.IMPSRC} -o ${.TARGET}
capsign: capsign.o capsign_tree.o ${COMMON} ${BUNDLE}
	${CC} ${LDFLAGS} -o ${.TARGET} ${.ALLSRC} -lprivateucl -lmd -lcrypto
elfcache: elfcache.o layout.o ${COMMON}
	${CC} ${LDFLAGS} -o ${.TARGET} ${.ALLSRC} -lcrypto
.PHONY: all

# Cache format headers must match the tools even when the installed host is older.
sys/elf_cache.h: ${SRCTOP}/sys/sys/elf_cache.h
	mkdir -p sys
	cp ${.ALLSRC} ${.TARGET}
sys/elf_cache_layout.h: ${SRCTOP}/sys/sys/elf_cache_layout.h
	mkdir -p sys
	cp ${.ALLSRC} ${.TARGET}
elfcache.o layout.o: sys/elf_cache.h sys/elf_cache_layout.h sys/capimage.h
