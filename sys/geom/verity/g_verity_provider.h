/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _GEOM_VERITY_PROVIDER_H_
#define _GEOM_VERITY_PROVIDER_H_
#include <geom/verity/g_verity_verify.h>
struct g_provider;
struct g_geom;
struct mount;
/*
 * Internal kernel constructor. To claim authenticated integrity, the caller
 * must establish root authority independently of this mechanism.
 * No taste, ioctl or runtime user control interface constructs providers.
 * Topology lock required. Success returns a read-only provider, NOT a BIP root
 * admission token. Boot integration must separately bind generation authority.
 * Each worker owns cache_entries hash blocks, two scratch blocks and a window.
 * buffer_budget bounds these allocations and worker records, not kernel thread
 * stacks, upstream BIOs or filesystem caches. Inputs have no implicit defaults.
 */
/*
 * No I/O/allocation/locking: validate target limits and the exact provider
 * buffer calculation. Output unchanged on error. Does not bound thread stacks,
 * queued BIOs or filesystem caches, and confers no boot/signature authority.
 */
int g_verity_provider_resources(const struct g_verity_root *, unsigned,
    uint64_t, uint64_t, uint64_t, size_t *);
int g_verity_provider_create(struct g_provider *, const char *,
    const struct g_verity_root *, unsigned, size_t, size_t, size_t,
    struct g_provider **);
/*
 * Copy the immutable root of this exact live verifier provider. Caller holds
 * topology and a reference keeping the provider alive. Output unchanged on
 * error. No signature authority or BIP admission follows from this query.
 */
int g_verity_provider_root(struct g_provider *, struct g_verity_root *);
/*
 * Check a busy, read-only UFS root against an independently authenticated root.
 * Caller excludes mount updates and owns the mount busy reference. Takes GEOM
 * topology internally; must not be called holding it. No signature authority,
 * boot-state transition or lasting storage seal is established by this check.
 */
int g_verity_check_ufs_root(struct mount *, const struct g_verity_root *);
/* Topology lock required. Refuses open providers; teardown is asynchronous. */
int g_verity_provider_destroy(struct g_geom *);
#endif
