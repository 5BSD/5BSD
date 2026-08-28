WORLDPACKAGE=	mac-capability
# The mac_capability MAC modules are the kernel half of the capability
# subsystem that authorityd(8)/serviced(8) depend on at boot, so they ship in
# the same (minimal) set as those daemons.  Section 4 manuals live in
# kernel-man by convention; the -tests artifacts are in mac-capability-tests.
PKG_SETS=	minimal
SUBPACKAGES=	dbg

PKG_LICENSES=	BSD2CLAUSE

.include <bsd.pkg.mk>
