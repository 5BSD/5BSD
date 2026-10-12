/* 5BSD: OpenBSD radix trie for pf tables (contrib/openbsd-pf/sys/net/radix.c),
 * renamed so it does not clash with the 5BSD kernel radix code. */
#ifndef _OBSD_RADIX_RENAME_H_
#define _OBSD_RADIX_RENAME_H_
#define rn_add_dupedkey obsd_rn_add_dupedkey
#define rn_add_radix_mask obsd_rn_add_radix_mask
#define rn_addmask obsd_rn_addmask
#define rn_addroute obsd_rn_addroute
#define rn_del_radix_mask obsd_rn_del_radix_mask
#define rn_delete obsd_rn_delete
#define rn_fixup_nodes obsd_rn_fixup_nodes
#define rn_init obsd_rn_init
#define rn_inithead obsd_rn_inithead
#define rn_initmask obsd_rn_initmask
#define rn_insert obsd_rn_insert
#define rn_lexobetter obsd_rn_lexobetter
#define rn_lift_node obsd_rn_lift_node
#define rn_link_dupedkey obsd_rn_link_dupedkey
#define rn_lookup obsd_rn_lookup
#define rn_match obsd_rn_match
#define rn_new_radix_mask obsd_rn_new_radix_mask
#define rn_newpair obsd_rn_newpair
#define rn_refines obsd_rn_refines
#define rn_satisfies_leaf obsd_rn_satisfies_leaf
#define rn_search obsd_rn_search
#define rn_search_m obsd_rn_search_m
#define rn_swap_nodes obsd_rn_swap_nodes
#define rn_walktree obsd_rn_walktree
#define rn_mkfreelist obsd_rn_mkfreelist
#define mask_rnhead obsd_mask_rnhead
#define rn_zeros obsd_rn_zeros
#define rn_ones obsd_rn_ones
#define addmask_key obsd_addmask_key
#define max_keylen obsd_max_keylen
#define rn_mkfreelist obsd_rn_mkfreelist
#define rtmask_pool obsd_rtmask_pool
#define rn_inithead0 obsd_rn_inithead0
#define radix_node obsd_radix_node
#define radix_node_head obsd_radix_node_head
#define radix_mask obsd_radix_mask
#endif
#include "../../../../../contrib/openbsd-pf/sys/net/radix.h"
