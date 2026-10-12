WORLDPACKAGE=libcryptocmp
PKG_SETS=minimal minimal-jail
SUBPACKAGES=dbg dev
COMPAT_PKGS=dbg dev lib
PKG_LICENSES=BSD2CLAUSE
PKG_LICENSELOGIC= multi
UCLSRC=${SRCTOP}/release/packages/ucl/libcryptocmp-all.ucl

PKG_DEPS.libcryptocmp+=libservice libfidl clibs

PKG_DEPS.libcryptocmp-dev+= libservice-dev libfidl-dev clibs-dev

.include <bsd.pkg.mk>
