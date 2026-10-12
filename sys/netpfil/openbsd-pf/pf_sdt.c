/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * DTrace SDT probes of OpenBSD PF.  Probe names and arguments are listed
 * in dtrace_pf(4).  Vendor files fire them through PF_SDTn()/REASON_SET
 * hooks marked "5BSD: DTrace"; the glue fires the test and ioctl probes.
 */

#include "openbsd_compat.h"

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

SDT_PROVIDER_DEFINE(pf);
SDT_PROBE_DEFINE3(pf, , reason, set, "int", "const char *", "int");
SDT_PROBE_DEFINE2(pf, frag, reassemble, entry, "struct mbuf *", "int");
SDT_PROBE_DEFINE2(pf, frag, reassemble6, entry, "struct mbuf *", "int");
SDT_PROBE_DEFINE2(pf, ioctl, ioctl, entry, "u_long", "int");
SDT_PROBE_DEFINE3(pf, ioctl, ioctl, return, "u_long", "int", "int");
SDT_PROBE_DEFINE1(pf, ioctl, xact, begin, "const char *");
SDT_PROBE_DEFINE2(pf, ioctl, xact, commit, "uint32_t", "const char *");
SDT_PROBE_DEFINE2(pf, ioctl, xact, rollback, "uint32_t", "const char *");
SDT_PROBE_DEFINE2(pf, ip, anchor, enter, "void *", "struct pf_ruleset *");
SDT_PROBE_DEFINE2(pf, ip, route_to, entry, "struct pf_pdesc *", "struct pf_state *");
SDT_PROBE_DEFINE1(pf, ip, rules, entry, "struct pf_pdesc *");
SDT_PROBE_DEFINE3(pf, ip, test, entry, "int", "int", "struct ifnet *");
SDT_PROBE_DEFINE3(pf, ip, test, finish, "int", "int", "struct ifnet *");
SDT_PROBE_DEFINE2(pf, ip6, route_to, entry, "struct pf_pdesc *", "struct pf_state *");
SDT_PROBE_DEFINE4(pf, log, pflog, packet, "struct pf_pdesc *", "int", "struct pf_rule *", "struct pf_rule *");
SDT_PROBE_DEFINE1(pf, nat, af_to, translate, "struct pf_pdesc *");
SDT_PROBE_DEFINE2(pf, nat, transaddr, entry, "struct pf_rule *", "struct pf_pdesc *");
SDT_PROBE_DEFINE1(pf, pflow, flow, export, "struct pf_state *");
SDT_PROBE_DEFINE1(pf, pfsync, packet, input, "struct mbuf *");
SDT_PROBE_DEFINE2(pf, pfsync, packet, send, "void *", "struct mbuf *");
SDT_PROBE_DEFINE2(pf, rule, jail, match, "struct pf_rule *", "int");
SDT_PROBE_DEFINE2(pf, state, purge, run, "u_int", "u_int");
SDT_PROBE_DEFINE3(pf, state, state, create, "struct pf_pdesc *", "struct pf_rule *", "struct pf_rule *");
SDT_PROBE_DEFINE1(pf, state, state, free, "struct pf_state *");
SDT_PROBE_DEFINE2(pf, state, state, insert, "struct pfi_kif *", "struct pf_state_key **");
SDT_PROBE_DEFINE1(pf, state, state, remove, "struct pf_state *");
SDT_PROBE_DEFINE3(pf, state, state, transition, "struct pf_state *", "int", "uint8_t");
SDT_PROBE_DEFINE1(pf, syncookie, cookie, send, "struct pf_pdesc *");
SDT_PROBE_DEFINE1(pf, syncookie, cookie, validate, "struct pf_pdesc *");
SDT_PROBE_DEFINE3(pf, table, addr, match, "struct pfr_ktable *", "struct pf_addr *", "int");
SDT_PROBE_DEFINE4(pf, table, addr, update, "struct pfr_ktable *", "struct pf_addr *", "struct pf_pdesc *", "int");
