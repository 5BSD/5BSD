.include <bsd.compat.pre.mk>

SCRIPTS=auto \
	adduser \
	bootconfig \
	checksum \
	config \
	docsinstall \
	entropy \
	fetchmissingdists \
	finalconfig \
	firmware \
	firmware-fetch \
	hardening \
	hostname \
	jail \
	keymap \
	mirrorselect \
	mount \
	mount_aux \
	netconfig \
	netconfig_ipv4 \
	netconfig_ipv6 \
	pkgbase \
	ports \
	rootpass \
	script \
	services \
	time \
	tzfspool \
	umount \
	verify-image \
	wlanconfig \
	zfsboot

BINDIR= ${LIBEXECDIR}/bsdinstall

FILES= hostname.subr repository.subr
FILESDIR= ${BINDIR}
MAN=

pkgbase: pkgbase.in
	sed "s|%%_ALL_libcompats%%|${_ALL_libcompats}|" < ${.ALLSRC} > ${.TARGET}

verify-image: ${SRCTOP}/tools/build/capimage/verify-stage.sh
	cp ${.ALLSRC} ${.TARGET}

CLEANFILES+= verify-image

.include <bsd.prog.mk>
