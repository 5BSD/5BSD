/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_BALLOON_HOST_H_
#define	_BHYVE_VIRTIO_BALLOON_HOST_H_

#include <sys/types.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_BALLOON_PFN_SHIFT		12
#define	BHYVE_BALLOON_PAGE_SIZE		(UINT64_C(1) << \
	    BHYVE_BALLOON_PFN_SHIFT)
#define	BHYVE_BALLOON_PFNS_PER_REQUEST	256U
#define	BHYVE_BALLOON_REQUEST_MAX	(BHYVE_BALLOON_PFNS_PER_REQUEST * \
	    sizeof(uint32_t))
#define	BHYVE_BALLOON_STAT_COUNT	10U
#define	BHYVE_BALLOON_STAT_SIZE		10U
#define	BHYVE_BALLOON_STATS_MAX_ENTRIES	1024U
#define	BHYVE_BALLOON_MAX_IOV		128U

struct virtio_balloon_pfn_result {
	size_t	vbpr_seen;
	size_t	vbpr_accepted;
	size_t	vbpr_rejected;
};

struct virtio_balloon_page_tracker {
	uint64_t	vbpt_lowmem_size;
	uint64_t	vbpt_highmem_base;
	uint64_t	vbpt_highmem_size;
	size_t		vbpt_host_page_size;
	uint8_t		*vbpt_bitmap;
	size_t		vbpt_bitmap_size;
};

struct virtio_balloon_accounting {
	uint32_t	vba_total_pages;
	uint32_t	vba_target_pages;
	uint32_t	vba_actual_pages;
};

struct virtio_balloon_stats {
	uint64_t	vbs_value[BHYVE_BALLOON_STAT_COUNT];
	uint16_t	vbs_present;
	size_t		vbs_entries;
	size_t		vbs_ignored;
};

typedef int (*virtio_balloon_pfn_cb)(void *, uint64_t);
typedef int (*virtio_balloon_range_cb)(void *, uint64_t, size_t);

int	virtio_balloon_process_pfns(const struct iovec *, size_t,
	    virtio_balloon_pfn_cb, void *, struct virtio_balloon_pfn_result *);
int	virtio_balloon_tracker_required(uint64_t, uint64_t, uint64_t,
	    size_t *);
int	virtio_balloon_tracker_init(struct virtio_balloon_page_tracker *,
	    uint64_t, uint64_t, uint64_t, size_t, uint8_t *, size_t);
int	virtio_balloon_tracker_inflate(struct virtio_balloon_page_tracker *,
	    uint64_t, uint64_t *, size_t *, bool *);
int	virtio_balloon_tracker_deflate(struct virtio_balloon_page_tracker *,
	    uint64_t, uint64_t *, size_t *);
int	virtio_balloon_tracker_inflate_transition(
	    struct virtio_balloon_page_tracker *, uint64_t, uint64_t *,
	    size_t *, bool *, bool *);
int	virtio_balloon_tracker_deflate_transition(
	    struct virtio_balloon_page_tracker *, uint64_t, uint64_t *,
	    size_t *, bool *);
int	virtio_balloon_tracker_release_all(
	    struct virtio_balloon_page_tracker *, virtio_balloon_range_cb,
	    void *);
int	virtio_balloon_accounting_init(struct virtio_balloon_accounting *,
	    uint64_t, uint32_t);
int	virtio_balloon_accounting_set_target(
	    struct virtio_balloon_accounting *, uint32_t, bool *);
int	virtio_balloon_accounting_set_actual(
	    struct virtio_balloon_accounting *, uint32_t);
void	virtio_balloon_accounting_reset(struct virtio_balloon_accounting *);
int	virtio_balloon_parse_stats(const struct iovec *, size_t,
	    struct virtio_balloon_stats *);

/*
 * Migration free-page-hint bridge (implemented in pci_virtio_balloon.c).
 *
 * The migration pre-copy path uses these to run one free-page-hint round and
 * collect the guest-reported free ranges through a range callback.  The
 * balloon device stays decoupled from the migration types: it only knows how
 * to publish a fresh command id, gather ranges into the supplied sink, and end
 * the round.  There is at most one balloon device per VM; the registry lookup
 * returns it (or NULL) so the migration path can discover it with no snapshot
 * or global-state coupling.
 */
struct pci_vtballoon_softc;

struct pci_vtballoon_softc *virtio_balloon_migration_lookup(void);
/*
 * Start a collection round: publish a fresh command id and install the sink.
 * Fails (leaving no round open) if the guest has not negotiated
 * FREE_PAGE_HINT or is not driver-OK.
 */
int	virtio_balloon_migration_start(struct pci_vtballoon_softc *,
	    virtio_balloon_range_cb, void *);
/* Non-blocking: has the guest signaled it reported every free page? */
bool	virtio_balloon_migration_complete(struct pci_vtballoon_softc *);
/*
 * Block until the guest finishes reporting or timeout_ms elapses, WITHOUT
 * ending the round.  The caller keeps the round open (holding the guest's
 * reported pages free) across the initial dirty snapshot, then calls
 * virtio_balloon_migration_finish().  Returns 0 only on a complete round.
 */
int	virtio_balloon_migration_wait(struct pci_vtballoon_softc *,
	    unsigned int timeout_ms);
/* End the round: publish DONE and detach the sink.  Idempotent. */
void	virtio_balloon_migration_finish(struct pci_vtballoon_softc *);
/*
 * Convenience for the pre-copy path: start a round and block until the guest
 * finishes reporting or timeout_ms elapses, then end the round.  Returns 0
 * only when a complete free set was collected; any other return means the
 * caller must copy every page (skip nothing).
 */
int	virtio_balloon_migration_collect(struct pci_vtballoon_softc *,
	    virtio_balloon_range_cb, void *, unsigned int timeout_ms);

#endif
