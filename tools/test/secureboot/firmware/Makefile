# SPDX-License-Identifier: BSD-2-Clause
# Reuse the maintained loader ABI, relocation code and PE conversion.
.include "${SRCTOP}/stand/efi/Makefile.inc"
.include <bsd.init.mk>
.if ${MACHINE} != "amd64"
.error This firmware probe is currently qualified only for amd64
.endif
PROBE?= probe
PROG= firmware_${PROBE}.sym
INTERNALPROG=
MAN=
SRCS= ${PROBE}.c self_reloc.c start.S
.PATH: ${SRCTOP}/stand/common ${SRCTOP}/stand/efi/loader/arch/amd64
CFLAGS+= -I${EFIINC} -I${EDK2INC} -I${EFIINCMD} -I${LDRSRC}
LDSCRIPT= ${SRCTOP}/stand/efi/loader/arch/amd64/amd64.ldscript
LDFLAGS+= -Wl,-T${LDSCRIPT},-Bsymbolic,-znotext,-znocombreloc -pie
DPADD+= ${LDSCRIPT}
FILES= firmware_${PROBE}.efi
CLEANFILES+= firmware_${PROBE}.efi
firmware_${PROBE}.efi: ${PROG}
	@if ${NM} ${.ALLSRC} | grep ' U '; then exit 1; fi
	SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} ${EFI_OBJCOPY} \
	    -j .peheader -j .text -j .sdata -j .data -j .dynamic -j .dynsym \
	    -j .rel.dyn -j .rela.dyn -j .reloc -j .eh_frame \
	    --output-target=${EFI_TARGET} ${.ALLSRC} ${.TARGET}
.include <bsd.prog.mk>
