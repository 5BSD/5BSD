WORLDPACKAGE=	switchboard
PKG_SETS=	minimal

PKG_LICENSES=	BSD2CLAUSE

# switchboard links against libcapbundle and libcapsulert.  capsule owns the
# bootstrap lifecycle and therefore depends on switchboard, not vice versa.
PKG_DEPS.switchboard+=	audit
PKG_DEPS.switchboard+=	libcapbundle
PKG_DEPS.switchboard+=	libcapability
PKG_DEPS.switchboard+=	libchannel
PKG_DEPS.switchboard+=	libcapsulert
PKG_DEPS.switchboard+=	libucl

.include <bsd.pkg.mk>
