WORLDPACKAGE=	serviced
PKG_SETS=	minimal

PKG_LICENSES=	BSD2CLAUSE

# serviced links against libcapbundle and liboraclert.  oracled owns the
# bootstrap lifecycle and therefore depends on serviced, not vice versa.
PKG_DEPS.serviced+=	libcapbundle
PKG_DEPS.serviced+=	liboraclert

.include <bsd.pkg.mk>
