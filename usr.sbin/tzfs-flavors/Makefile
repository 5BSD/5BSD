.include <src.opts.mk>

# The OS-image flavor catalog for tzfsd(8): a config drop-in that declares the
# freebsd/linux flavors plus the tools that produce their baked artifacts.  It
# is packaged separately from the tzfsd broker so distro curation stays
# decoupled and can be installed, versioned, or removed on its own.
PACKAGE=	tzfs-flavors

SCRIPTS=	tzfs-flavor-linux.sh \
		tzfs-flavor-freebsd.sh
SCRIPTSDIR=	/usr/libexec

# Flavor-catalog drop-in read by tzfsd(8) from /Capabilities/Config/tzfsd.d/.
CONFS=		flavors.ucl
CONFSDIR=	/Capabilities/Config/tzfsd.d

MAN=		tzfs-flavors.7

.include <bsd.prog.mk>
