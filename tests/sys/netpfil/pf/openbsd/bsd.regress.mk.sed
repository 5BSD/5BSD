# Adapt contrib/openbsd-pf/share/mk/bsd.regress.mk (OpenBSD make) for 5BSD
# bmake.  Plumbing only; the upstream file stays verbatim in contrib.
#  - OpenBSD's :L modifier lowercases; bmake spells that :tl (bmake :L
#    yields the variable name, which made REGRESS_FAIL_EARLY=no ineffective).
#  - NOMAN= is OpenBSD's switch; FreeBSD bsd.prog.mk needs MAN= as well.
#  - BSDSRCDIR comes from OpenBSD's bsd.own.mk; default it to /usr/src.
s/:L}/:tl}/g
s/^NOMAN=$/NOMAN=\
MAN=\
BSDSRCDIR?=\/usr\/src/
