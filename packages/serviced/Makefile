WORLDPACKAGE=	serviced
PKG_SETS=	minimal

PKG_LICENSES=	BSD2CLAUSE

# serviced links against libcapbundle and libauthorityrt.  authorityd owns the
# bootstrap lifecycle and therefore depends on serviced, not vice versa.
PKG_DEPS.serviced+=	audit
PKG_DEPS.serviced+=	libcapbundle
PKG_DEPS.serviced+=	libcapability
PKG_DEPS.serviced+=	libchannel
PKG_DEPS.serviced+=	libauthorityrt
PKG_DEPS.serviced+=	libucl

.include <bsd.pkg.mk>
