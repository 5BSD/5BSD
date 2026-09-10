.include <bsd.compat.pre.mk>

SCRIPTS=auto \
	adduser \
	bootconfig \
	capabilitypolicy \
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
	rootpass \
	script \
	services \
	time \
	tzfspool \
	umount \
	wlanconfig \
	zfsboot

BINDIR= ${LIBEXECDIR}/bsdinstall

FILES= hostname.subr
FILESDIR= ${BINDIR}
MAN=

pkgbase: pkgbase.in
	sed "s|%%_ALL_libcompats%%|${_ALL_libcompats}|" < ${.ALLSRC} > ${.TARGET}

.include <bsd.prog.mk>
