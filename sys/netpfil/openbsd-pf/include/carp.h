/*
 * 5BSD: carp
 *
 * carp(4) is not an interface on 5BSD: vhids live on their parent
 * interface, so pf.c's IFT_CARP paths stay compiled out (NCARP 0).
 * if_pfsync.c defines PFSYNC_CARP_DEMOTE before including this header:
 * its demotion of the "carp" interface group maps onto the global
 * net.inet.carp.demotion, see carp_group_demote_adj() in pf_pfsync.c.
 */
#ifdef PFSYNC_CARP_DEMOTE
#define NCARP 1
#else
#define NCARP 0
#endif
