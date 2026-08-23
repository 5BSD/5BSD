/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/linker_set.h>
#include <sys/uio.h>

#include <dev/virtio/balloon/virtio_balloon.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <vmmapi.h>

#include <assert.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "mevent.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "virtio.h"
#include "virtio_balloon_host.h"
#include "virtio_pci_modern_probes.h"

/*
 * Release-ledger anchors for the live balloon data and configuration paths.
 * VIRTIO_ACTIVATION_ASSERTION: config-change-and-actual-update
 * VIRTIO_ACTIVATION_ASSERTION: discard-and-deflate
 * VIRTIO_ACTIVATION_ASSERTION: lowmem-deflate-request
 * VIRTIO_ACTIVATION_ASSERTION: inflate-pfn-consumption
 * VIRTIO_ACTIVATION_ASSERTION: statistics-sample-and-refresh
 * VIRTIO_ACTIVATION_ASSERTION: free-page-hint-command-and-discard
 * VIRTIO_ACTIVATION_ASSERTION: free-page-report-discard
 * VIRTIO_ACTIVATION_ASSERTION: page-poison-config-and-report-preservation
 */

#define	VTBALLOON_RINGSZ		128
#define	VTBALLOON_INFLATE_QUEUE		0
#define	VTBALLOON_DEFLATE_QUEUE		1
#define	VTBALLOON_STATS_QUEUE		2
#define	VTBALLOON_FREE_PAGE_QUEUE	3
#define	VTBALLOON_REPORTING_QUEUE	4
#define	VTBALLOON_NVQ			5
#define	VTBALLOON_STATS_INTERVAL_MIN	1
#define	VTBALLOON_STATS_INTERVAL_MAX	3600
#define	VTBALLOON_CMD_ID_STOP		0U
#define	VTBALLOON_CMD_ID_DONE		1U
#define	VTBALLOON_CMD_ID_FIRST		2U
#define	VTBALLOON_SNAPSHOT_MAGIC	0x314c4142U	/* "BAL1" on disk */
#define	VTBALLOON_SNAPSHOT_VERSION	6U

struct pci_vtballoon_softc {
	struct virtio_softc vbsc_vs;
	struct vqueue_info vbsc_vq[VTBALLOON_NVQ];
	struct virtio_consts vbsc_consts;
	pthread_mutex_t vbsc_mtx;
	struct virtio_balloon_accounting vbsc_accounting;
	struct virtio_balloon_page_tracker vbsc_tracker;
	struct virtio_balloon_stats vbsc_stats;
	struct vi_req vbsc_stats_req;
	struct mevent *vbsc_stats_evp;
	uint8_t *vbsc_bitmap;
	uint64_t vbsc_lowmem_size;
	uint64_t vbsc_highmem_base;
	uint64_t vbsc_highmem_size;
	uint32_t vbsc_free_page_hint_cmd_id;
	uint32_t vbsc_poison_val;
	unsigned int vbsc_debug;
	bool vbsc_free_page_hint_active;
	bool vbsc_stats_held;
	bool vbsc_stats_valid;
	/*
	 * Migration free-page-hint collection.  These are pure runtime control
	 * state for a host-driven hint round and are never snapshotted: a
	 * checkpoint pause quiesces the device and any in-flight round is
	 * abandoned (skip nothing) rather than carried across a save.
	 */
	virtio_balloon_range_cb vbsc_migration_sink;
	void *vbsc_migration_sink_arg;
	pthread_cond_t vbsc_migration_cv;
	uint32_t vbsc_migration_next_cmd_id;
	bool vbsc_migration_cv_ready;
	bool vbsc_migration_round;
	bool vbsc_migration_complete;
	/*
	 * Retained STOP command descriptor for an in-flight migration round.
	 * The guest driver returns its reported-free pages to the allocator as
	 * soon as this descriptor is completed, so the round holds it uncompleted
	 * until virtio_balloon_migration_finish() runs -- after the collector has
	 * taken the initial dirty snapshot -- and only then releases the guest.
	 */
	struct vi_req vbsc_migration_stop_req;
	bool vbsc_migration_stop_held;
};

struct vtballoon_pfn_context {
	struct pci_vtballoon_softc *sc;
	bool inflate;
};

/*
 * At most one balloon device exists per VM.  The migration pre-copy path
 * discovers it through this registry rather than reaching into snapshot or
 * global device tables.
 */
static pthread_mutex_t pci_vtballoon_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct pci_vtballoon_softc *pci_vtballoon_registry;

static void pci_vtballoon_reset(void *);
static int pci_vtballoon_qreset(void *, struct vqueue_info *, uint64_t);
static void pci_vtballoon_notify(void *, struct vqueue_info *);
static int pci_vtballoon_cfgread(void *, int, int, uint32_t *);
static int pci_vtballoon_cfgwrite(void *, int, int, uint32_t);
static void pci_vtballoon_stats_timer(int, enum ev_type, void *);
static int pci_vtballoon_suspend_device(void *);
static int pci_vtballoon_pause(void *);
static int pci_vtballoon_release_range(void *, uint64_t, size_t);
#ifdef BHYVE_SNAPSHOT
static int pci_vtballoon_snapshot(void *, struct vm_snapshot_meta *);
static int pci_vtballoon_snapshot_validate(struct vm_snapshot_meta *);
#endif

static const struct virtio_consts vtballoon_vi_consts = {
	.vc_name = "vtballoon",
	.vc_nvq = 2,
	.vc_cfgsize = sizeof(struct virtio_balloon_config),
	.vc_reset = pci_vtballoon_reset,
	.vc_qreset = pci_vtballoon_qreset,
	.vc_qnotify = pci_vtballoon_notify,
	.vc_cfgread = pci_vtballoon_cfgread,
	.vc_cfgwrite = pci_vtballoon_cfgwrite,
	.vc_suspend = pci_vtballoon_suspend_device,
	.vc_resume_device = vi_pci_lifecycle_noop,
	.vc_pause = pci_vtballoon_pause,
	.vc_resume = vi_pci_lifecycle_noop,
#ifdef BHYVE_SNAPSHOT
	.vc_snapshot = pci_vtballoon_snapshot,
#endif
	/*
	 * The statistics queue retains its head descriptor for timer-driven
	 * completion.  Do not promise VIRTIO_F_IN_ORDER until that asynchronous
	 * path has an explicit ordering contract and qualification.
	 */
	.vc_hv_caps = VIRTIO_BALLOON_F_MUST_TELL_HOST | VIRTIO_F_RING_RESET |
	    VIRTIO_F_SUSPEND,
	/*
	 * Linux virtio-balloon intentionally clears ACCESS_PLATFORM because
	 * its PFN and free-page paths do not use the DMA API.
	 */
	.vc_access_platform_ineligible = true,
};

static bool
pci_vtballoon_stats_req_valid(const struct pci_vtballoon_softc *sc,
    const struct vi_req *req)
{
	const struct vqueue_info *vq;

	vq = &sc->vbsc_vq[VTBALLOON_STATS_QUEUE];
	if (!req->outstanding || !vq_is_allocated(vq) ||
	    req->queue_generation != vq->vq_generation ||
	    req->idx >= vq->vq_qsize || req->descriptor_count == 0 ||
	    req->descriptor_count > vq->vq_qsize)
		return (false);
	if (vq->vq_layout == VIRTIO_QUEUE_PACKED)
		return (req->packed_head < vq->vq_qsize);
	return (req->completion_id == req->idx);
}

static void
pci_vtballoon_stats_release(struct pci_vtballoon_softc *sc)
{
	struct vqueue_info *vq;

	if (!sc->vbsc_stats_held)
		return;
	vq = &sc->vbsc_vq[VTBALLOON_STATS_QUEUE];
	if (!pci_vtballoon_stats_req_valid(sc, &sc->vbsc_stats_req)) {
		if (sc->vbsc_stats_req.outstanding)
			vq_discard_req(vq, &sc->vbsc_stats_req);
		sc->vbsc_stats_held = false;
		memset(&sc->vbsc_stats_req, 0, sizeof(sc->vbsc_stats_req));
		vi_set_needs_reset(&sc->vbsc_vs);
		return;
	}
	vq_relchain_req(vq, &sc->vbsc_stats_req, 0);
	VIRTIO_PROBE_BALLOON_STATS(sc->vbsc_vs.vs_vc->vc_name, "refresh",
	    sc->vbsc_stats.vbs_present, (uint32_t)sc->vbsc_stats.vbs_entries,
	    (uint32_t)sc->vbsc_stats.vbs_ignored);
	if (sc->vbsc_debug != 0)
		EPRINTLN("vtballoon: statistics refresh entries=%zu present=%#x",
		    sc->vbsc_stats.vbs_entries, sc->vbsc_stats.vbs_present);
	sc->vbsc_stats_held = false;
	memset(&sc->vbsc_stats_req, 0, sizeof(sc->vbsc_stats_req));
	vq_endchains(vq, 0);
}

static int
pci_vtballoon_suspend_device(void *vsc)
{
	struct pci_vtballoon_softc *sc;

	sc = vsc;
	/*
	 * A retained statistics descriptor is live queue ownership, not
	 * suspend state.  The common guest-suspend path already holds vs_mtx
	 * and has published the queue-ownership fence, so complete it before
	 * the SUSPEND status bit becomes visible.  The guest will submit a
	 * fresh sample after resume.
	 */
	pci_vtballoon_stats_release(sc);
	return (0);
}

static int
pci_vtballoon_pause(void *vsc)
{
	struct pci_vtballoon_softc *sc;
	int error;

	sc = vsc;
	VS_LOCK(&sc->vbsc_vs);
	/*
	 * Checkpoint pause is entered without vs_mtx held.  Use the same
	 * ownership-drain operation under the checkpoint queue fence.
	 */
	error = pci_vtballoon_suspend_device(sc);
	if (error == 0 &&
	    (sc->vbsc_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0)
		error = EIO;
	VS_UNLOCK(&sc->vbsc_vs);
	return (error);
}

static void
pci_vtballoon_stats_timer(int msecs __unused, enum ev_type type __unused,
    void *arg)
{
	struct pci_vtballoon_softc *sc;

	assert(type == EVF_TIMER);
	sc = arg;
	VS_LOCK(&sc->vbsc_vs);
	if (!sc->vbsc_vs.vs_quiescing && !sc->vbsc_vs.vs_suspended &&
	    !sc->vbsc_vs.vs_checkpoint_paused &&
	    (sc->vbsc_vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0)
		pci_vtballoon_stats_release(sc);
	VS_UNLOCK(&sc->vbsc_vs);
}

static int
pci_vtballoon_pfn(void *arg, uint64_t gpa)
{
	struct vtballoon_pfn_context *context;
	struct pci_vtballoon_softc *sc;
	uint64_t discard_gpa;
	size_t discard_len;
	bool changed, ready;
	int error;

	context = arg;
	sc = context->sc;
	if (!context->inflate) {
		error = virtio_balloon_tracker_deflate_transition(
		    &sc->vbsc_tracker, gpa, &discard_gpa, &discard_len,
		    &changed);
		if (error != 0 || discard_len == 0)
			return (error);
		error = vi_platform_undiscard_ram(&sc->vbsc_vs, discard_gpa,
		    discard_len);
		VIRTIO_PROBE_BALLOON_UNDISCARD(sc->vbsc_vs.vs_vc->vc_name,
		    discard_gpa, discard_len, error);
		/*
		 * Deflation transfers the page back to the driver when this
		 * status-less request is completed.  MADV_WILLNEED is only a host
		 * paging hint: failure cannot revoke that transfer or be reported to
		 * the driver.  Keep the ownership transition and expose the host
		 * failure through the probe above, matching the established QEMU
		 * device-model behavior.
		 */
		return (0);
	}
	error = virtio_balloon_tracker_inflate_transition(&sc->vbsc_tracker,
	    gpa, &discard_gpa, &discard_len, &ready, &changed);
	if (error != 0 || !ready)
		return (error);
	error = vi_platform_discard_ram(&sc->vbsc_vs, discard_gpa,
	    discard_len);
	VIRTIO_PROBE_BALLOON_DISCARD(sc->vbsc_vs.vs_vc->vc_name,
	    discard_gpa, discard_len, error);
	/*
	 * Inflation transfers ownership to the device before completion.  Host
	 * discard is an optional reclamation optimization, so retain the exact
	 * guest ownership bit even if that optimization fails.  There is no
	 * request status field with which to report a different result.
	 */
	return (0);
}

static void
pci_vtballoon_notify(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtballoon_softc *sc;
	struct vtballoon_pfn_context context;
	struct virtio_balloon_pfn_result result;
	struct virtio_balloon_stats stats;
	struct iovec iov[VTBALLOON_RINGSZ];
	struct vi_req req;
	uint16_t budget;
	int error, n;

	sc = vsc;
	if (vq->vq_num == VTBALLOON_FREE_PAGE_QUEUE) {
		uint32_t command;
		bool retain_stop = false;

		if ((sc->vbsc_vs.vs_negotiated_caps &
		    VIRTIO_BALLOON_F_FREE_PAGE_HINT) == 0) {
			vi_set_needs_reset(&sc->vbsc_vs);
			return;
		}
		/*
		 * Linux supplies the four-byte command and the writable page
		 * ranges as separate buffers.  Accept the QEMU-compatible
		 * combined shape as well, but require all readable command
		 * fragments to total exactly four bytes.
		 */
		budget = vq->vq_qsize;
		while (budget-- != 0 && vq_has_descs(vq)) {
			size_t command_bytes;
			bool pages_match;

			n = vq_getchain(vq, iov, nitems(iov), &req);
			if (n <= 0)
				break;
			if (n > (int)nitems(iov) || req.readable < 0 ||
			    req.writable < 0 || req.readable > n ||
			    req.writable > n ||
			    req.readable != n - req.writable ||
			    (!req.ordered && req.readable != 0 &&
			    req.writable != 0)) {
				VIRTIO_PROBE_ERROR(sc->vbsc_vs.vs_vc->vc_name,
				    "invalid-free-page-hint-chain");
				vi_set_needs_reset(&sc->vbsc_vs);
				vq_relchain_req(vq, &req, 0);
				break;
			}
			command_bytes = 0;
			for (int i = 0; i < req.readable; i++) {
				if (iov[i].iov_len >
				    sizeof(command) - command_bytes) {
					command_bytes = sizeof(command) + 1;
					break;
				}
				memcpy((uint8_t *)&command + command_bytes,
				    iov[i].iov_base, iov[i].iov_len);
				command_bytes += iov[i].iov_len;
			}
			if (req.readable != 0 &&
			    command_bytes != sizeof(command)) {
				VIRTIO_PROBE_ERROR(sc->vbsc_vs.vs_vc->vc_name,
				    "invalid-free-page-hint-chain");
				vi_set_needs_reset(&sc->vbsc_vs);
				vq_relchain_req(vq, &req, 0);
				break;
			}
			if (req.readable != 0) {
				command = le32toh(command);
				pages_match = false;
				if (command == VTBALLOON_CMD_ID_STOP &&
				    (sc->vbsc_free_page_hint_active ||
				    sc->vbsc_free_page_hint_cmd_id ==
				    VTBALLOON_CMD_ID_STOP)) {
					/*
					 * The guest has reported every free page
					 * for this round.  When a migration
					 * collection is in progress, mark it
					 * complete and wake the collector; the
					 * collector publishes DONE itself, so
					 * only refresh the config change here for
					 * the non-migration case.
					 */
					sc->vbsc_free_page_hint_active = false;
					if (sc->vbsc_migration_round) {
						sc->vbsc_migration_complete = true;
						/*
						 * Hold this STOP descriptor
						 * uncompleted so the guest keeps
						 * its reported-free pages
						 * allocated (and thus unwritten)
						 * until the collector has taken
						 * the initial dirty snapshot.
						 * Completing it now would let the
						 * guest reallocate and write a
						 * reported page before the
						 * snapshot's clear, losing that
						 * write.  finish() releases it.
						 * A second STOP arriving before
						 * finish() (a misbehaving guest)
						 * is completed normally rather
						 * than overwriting and leaking the
						 * held descriptor.
						 */
						if (!sc->vbsc_migration_stop_held) {
							sc->vbsc_migration_stop_req =
							    req;
							sc->vbsc_migration_stop_held =
							    true;
							retain_stop = true;
						}
						if (sc->vbsc_migration_cv_ready)
							pthread_cond_broadcast(
							    &sc->vbsc_migration_cv);
						VIRTIO_PROBE_BALLOON_HINT(
						    sc->vbsc_vs.vs_vc->vc_name,
						    "done", command, UINT64_MAX,
						    0);
					} else {
						sc->vbsc_free_page_hint_cmd_id =
						    VTBALLOON_CMD_ID_DONE;
						if (sc->vbsc_debug != 0)
							EPRINTLN("vtballoon: "
							    "free-page hint round "
							    "done");
						VIRTIO_PROBE_BALLOON_HINT(
						    sc->vbsc_vs.vs_vc->vc_name,
						    "done", command, UINT64_MAX,
						    0);
						vi_pci_config_changed(
						    &sc->vbsc_vs);
					}
				} else if (command ==
				    sc->vbsc_free_page_hint_cmd_id &&
				    command >= VTBALLOON_CMD_ID_FIRST) {
					sc->vbsc_free_page_hint_active = true;
					pages_match = true;
					VIRTIO_PROBE_BALLOON_HINT(
					    sc->vbsc_vs.vs_vc->vc_name, "start",
					    command, UINT64_MAX, 0);
				} else {
					VIRTIO_PROBE_BALLOON_HINT(
					    sc->vbsc_vs.vs_vc->vc_name, "stale",
					    command, UINT64_MAX, 0);
				}
			} else {
				/*
				 * Linux publishes page-only buffers after the
				 * current command buffer.  They inherit only an
				 * already active command; a combined buffer must
				 * carry that exact command itself.
				 */
				pages_match = sc->vbsc_free_page_hint_active;
			}
			/*
			 * PAGE_POISON with a non-zero poison_val requires the
			 * content of hinted pages to be preserved (section
			 * 5.5.6.6): the MADV_FREE-backed discard lazily
			 * replaces the poison pattern with zeros, and marking
			 * the range as migration-skippable would deliver
			 * zeroed pages on the destination.  A zero poison_val
			 * is exactly what a discard (or a skipped, zero-filled
			 * destination page) reproduces, so the optimization
			 * remains valid in that case.  The command protocol is
			 * unaffected either way; the ranges are simply
			 * acknowledged without being consumed.
			 */
			if (sc->vbsc_free_page_hint_active && pages_match &&
			    ((sc->vbsc_vs.vs_negotiated_caps &
			    VIRTIO_BALLOON_F_PAGE_POISON) == 0 ||
			    sc->vbsc_poison_val == 0)) {
				for (int i = req.readable; i < n; i++) {
					uint64_t gpa;

					error = vi_platform_reverse_ram(
					    &sc->vbsc_vs, iov[i].iov_base,
					    iov[i].iov_len, &gpa);
					/*
					 * Record the guest-physical range into
					 * the migration free set before the
					 * optional discard.  Only a range whose
					 * host address resolves is trusted;
					 * anything else is simply not marked, so
					 * the pre-copy path copies it.
					 */
					if (error == 0 &&
					    sc->vbsc_migration_sink != NULL)
						(void)sc->vbsc_migration_sink(
						    sc->vbsc_migration_sink_arg,
						    gpa, iov[i].iov_len);
					if (error == 0)
						error = vi_platform_discard_ram(
						    &sc->vbsc_vs, gpa,
						    iov[i].iov_len);
					VIRTIO_PROBE_BALLOON_DISCARD(
					    sc->vbsc_vs.vs_vc->vc_name,
					    error == 0 ? gpa : UINT64_MAX,
					    iov[i].iov_len, error);
					VIRTIO_PROBE_BALLOON_HINT(
					    sc->vbsc_vs.vs_vc->vc_name, "range",
					    sc->vbsc_free_page_hint_cmd_id,
					    error == 0 ? gpa : UINT64_MAX,
					    error == 0 ?
					    (int64_t)iov[i].iov_len :
					    -(int64_t)error);
					if (error == 0 && sc->vbsc_debug != 0)
						EPRINTLN("vtballoon: free-page "
						    "hint gpa=%#jx len=%zu "
						    "command=%u",
						    (uintmax_t)gpa,
						    iov[i].iov_len,
						    sc->vbsc_free_page_hint_cmd_id);
					if (error != 0) {
						sc->vbsc_free_page_hint_active =
						    false;
						sc->vbsc_free_page_hint_cmd_id =
						    VTBALLOON_CMD_ID_STOP;
						if (sc->vbsc_debug != 0)
							EPRINTLN("vtballoon: "
							    "free-page hint "
							    "stopped: %s",
							    strerror(error));
						vi_pci_config_changed(
						    &sc->vbsc_vs);
						break;
					}
				}
			}
			if (retain_stop)
				break;
			vq_relchain_req(vq, &req, 0);
		}
		vq_endchains(vq, !vq_has_descs(vq));
		return;
	}
	if (vq->vq_num == VTBALLOON_REPORTING_QUEUE) {
		if ((sc->vbsc_vs.vs_negotiated_caps &
		    VIRTIO_BALLOON_F_PAGE_REPORTING) == 0) {
			vi_set_needs_reset(&sc->vbsc_vs);
			return;
		}
		/*
		 * Reporting descriptors are writable guest-RAM ranges.  The
		 * guest owns neither their contents nor reuse until completion.
		 * Discard is an optional optimization, so an unmappable or
		 * unaligned individual range is ignored and the report is still
		 * acknowledged as required by section 5.5.6.7.
		 */
		budget = vq->vq_qsize;
		while (budget-- != 0 && vq_has_descs(vq)) {
			n = vq_getchain(vq, iov, nitems(iov), &req);
			if (n <= 0)
				break;
			if (n > (int)nitems(iov) || req.readable != 0 ||
			    req.writable != n) {
				VIRTIO_PROBE_ERROR(sc->vbsc_vs.vs_vc->vc_name,
				    "invalid-reporting-chain");
				vq_relchain_req(vq, &req, 0);
				continue;
			}
			for (int i = 0; i < n; i++) {
				uint64_t gpa;

				/*
				 * PAGE_POISON requires reported pages to retain
				 * poison_val.  Replacing their backing with a
				 * host-defined zero or lazy-allocation pattern
				 * would violate section 5.5.6.7, so acknowledge
				 * without applying the optional discard
				 * optimization.
				 */
				if ((sc->vbsc_vs.vs_negotiated_caps &
				    VIRTIO_BALLOON_F_PAGE_POISON) != 0) {
					if (sc->vbsc_debug != 0)
						EPRINTLN("vtballoon: preserving "
						    "poisoned free-page report "
						    "len=%zu", iov[i].iov_len);
					continue;
				}
				error = vi_platform_reverse_ram(&sc->vbsc_vs,
				    iov[i].iov_base, iov[i].iov_len, &gpa);
				if (error == 0)
					error = vi_platform_discard_ram(
					    &sc->vbsc_vs, gpa, iov[i].iov_len);
				if (error == 0 && sc->vbsc_debug != 0)
					EPRINTLN("vtballoon: free-page report "
					    "gpa=%#jx len=%zu", (uintmax_t)gpa,
					    iov[i].iov_len);
				VIRTIO_PROBE_BALLOON_DISCARD(
				    sc->vbsc_vs.vs_vc->vc_name,
				    error == 0 ? gpa : UINT64_MAX,
				    iov[i].iov_len, error);
			}
			vq_relchain_req(vq, &req, 0);
		}
		vq_endchains(vq, !vq_has_descs(vq));
		return;
	}
	if (vq->vq_num == VTBALLOON_STATS_QUEUE) {
		if ((sc->vbsc_vs.vs_negotiated_caps &
		    VIRTIO_BALLOON_F_STATS_VQ) == 0) {
			vi_set_needs_reset(&sc->vbsc_vs);
			return;
		}
		/*
		 * VirtIO 1.4 section 5.5.6.3 requires the device to retain at
		 * most one statistics buffer.  Returning that buffer asks the
		 * driver for a fresh sample; the periodic timer performs that
		 * completion, so notification only acquires and parses.
		 */
		if (sc->vbsc_stats_held || !vq_has_descs(vq))
			return;
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0)
			return;
		if (n > (int)nitems(iov) || req.readable != n ||
		    req.writable != 0 ||
		    virtio_balloon_parse_stats(iov, (size_t)n, &stats) != 0) {
			VIRTIO_PROBE_ERROR(sc->vbsc_vs.vs_vc->vc_name,
			    "invalid-stats-chain");
			vq_relchain_req(vq, &req, 0);
			vq_endchains(vq, !vq_has_descs(vq));
			return;
		}
		sc->vbsc_stats = stats;
		sc->vbsc_stats_valid = true;
		sc->vbsc_stats_req = req;
		sc->vbsc_stats_held = true;
		VIRTIO_PROBE_BALLOON_STATS(sc->vbsc_vs.vs_vc->vc_name, "sample",
		    stats.vbs_present, (uint32_t)stats.vbs_entries,
		    (uint32_t)stats.vbs_ignored);
		if (sc->vbsc_debug != 0)
			EPRINTLN("vtballoon: statistics sample entries=%zu "
			    "ignored=%zu present=%#x", stats.vbs_entries,
			    stats.vbs_ignored, stats.vbs_present);
		return;
	}
	context.sc = sc;
	context.inflate = vq->vq_num == VTBALLOON_INFLATE_QUEUE;
	if (!context.inflate && vq->vq_num != VTBALLOON_DEFLATE_QUEUE) {
		vi_set_needs_reset(&sc->vbsc_vs);
		return;
	}
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0)
			break;
		if (n > (int)nitems(iov) || req.readable != n ||
		    req.writable != 0) {
			VIRTIO_PROBE_ERROR(sc->vbsc_vs.vs_vc->vc_name,
			    "invalid-pfn-chain");
			vq_relchain_req(vq, &req, 0);
			continue;
		}
		memset(&result, 0, sizeof(result));
		error = virtio_balloon_process_pfns(iov, (size_t)n,
		    pci_vtballoon_pfn, &context, &result);
		if (error == E2BIG)
			vi_set_needs_reset(&sc->vbsc_vs);
		VIRTIO_PROBE_BALLOON_REQUEST(sc->vbsc_vs.vs_vc->vc_name,
		    vq->vq_num, (uint32_t)result.vbpr_seen,
		    (uint32_t)result.vbpr_rejected, error);
		if (sc->vbsc_debug != 0)
			EPRINTLN("vtballoon: %s request seen=%zu accepted=%zu "
			    "rejected=%zu error=%d",
			    context.inflate ? "inflate" : "deflate",
			    result.vbpr_seen, result.vbpr_accepted,
			    result.vbpr_rejected, error);
		vq_relchain_req(vq, &req, 0);
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

/*
 * Abandon an in-flight migration collection round.  Called from paths that
 * invalidate the free-page queue (device reset, queue reset).  A blocked
 * collector wakes to find no round in progress and falls back to copying every
 * page, so an interrupted round never yields a partial free set.
 */
static void
pci_vtballoon_migration_abandon(struct pci_vtballoon_softc *sc)
{

	if (!sc->vbsc_migration_round)
		return;
	sc->vbsc_migration_sink = NULL;
	sc->vbsc_migration_sink_arg = NULL;
	sc->vbsc_migration_round = false;
	sc->vbsc_migration_complete = false;
	/*
	 * A retained STOP descriptor belongs to a queue that is being reset out
	 * from under this round.  Release its ownership (without publishing a
	 * used entry into a ring that is going away) so no descriptor leaks.
	 */
	if (sc->vbsc_migration_stop_held) {
		if (sc->vbsc_migration_stop_req.outstanding)
			vq_discard_req(&sc->vbsc_vq[VTBALLOON_FREE_PAGE_QUEUE],
			    &sc->vbsc_migration_stop_req);
		sc->vbsc_migration_stop_held = false;
		memset(&sc->vbsc_migration_stop_req, 0,
		    sizeof(sc->vbsc_migration_stop_req));
	}
	if (sc->vbsc_migration_cv_ready)
		pthread_cond_broadcast(&sc->vbsc_migration_cv);
}

static void
pci_vtballoon_reset(void *vsc)
{
	struct pci_vtballoon_softc *sc;
	int error;

	sc = vsc;
	pci_vtballoon_migration_abandon(sc);
	if (sc->vbsc_stats_held)
		vq_discard_req(&sc->vbsc_vq[VTBALLOON_STATS_QUEUE],
		    &sc->vbsc_stats_req);
	sc->vbsc_stats_held = false;
	sc->vbsc_stats_valid = false;
	sc->vbsc_free_page_hint_cmd_id =
	    (sc->vbsc_consts.vc_hv_caps &
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT) != 0 ?
	    VTBALLOON_CMD_ID_FIRST : VTBALLOON_CMD_ID_STOP;
	sc->vbsc_free_page_hint_active = false;
	sc->vbsc_poison_val = 0;
	memset(&sc->vbsc_stats_req, 0, sizeof(sc->vbsc_stats_req));
	memset(&sc->vbsc_stats, 0, sizeof(sc->vbsc_stats));
	error = virtio_balloon_tracker_release_all(&sc->vbsc_tracker,
	    pci_vtballoon_release_range, sc);
	if (error != 0) {
		VIRTIO_PROBE_ERROR(sc->vbsc_vs.vs_vc->vc_name,
		    "reset-undiscard-failed");
	} else {
		virtio_balloon_accounting_reset(&sc->vbsc_accounting);
	}
	vi_reset_dev(&sc->vbsc_vs);
	/*
	 * Common reset clears the previous incarnation's runtime latch.  A
	 * failed host discard cancellation leaves the retained ownership bitmap
	 * and host memory potentially inconsistent, so publish the new
	 * incarnation as incomplete only after that reset.
	 */
	if (error != 0)
		vi_snapshot_restore_incomplete(&sc->vbsc_vs);
}

static int
pci_vtballoon_release_range(void *arg, uint64_t gpa, size_t length)
{
	struct pci_vtballoon_softc *sc;
	int error;

	sc = arg;
	error = vi_platform_undiscard_ram(&sc->vbsc_vs, gpa, length);
	VIRTIO_PROBE_BALLOON_UNDISCARD(sc->vbsc_vs.vs_vc->vc_name, gpa,
	    length, error);
	return (error);
}

static int
pci_vtballoon_qreset(void *vsc, struct vqueue_info *vq, uint64_t generation)
{
	struct pci_vtballoon_softc *sc;

	sc = vsc;
	if (vq->vq_generation != generation)
		return (ESTALE);
	/*
	 * The statistics queue deliberately retains one driver-readable
	 * descriptor between refreshes.  A selective queue reset revokes that
	 * descriptor without completing it.  The common transport has already
	 * detached the queue and advanced its generation before this callback,
	 * so retaining the old request would both prevent reacquisition and
	 * eventually turn a valid queue reset into NEEDS_RESET.
	 */
	if (vq->vq_num == VTBALLOON_STATS_QUEUE) {
		if (sc->vbsc_stats_held)
			vq_discard_req(vq, &sc->vbsc_stats_req);
		sc->vbsc_stats_held = false;
		memset(&sc->vbsc_stats_req, 0, sizeof(sc->vbsc_stats_req));
	} else if (vq->vq_num == VTBALLOON_FREE_PAGE_QUEUE) {
		/*
		 * Queue reset revokes the command buffer that established the
		 * active phase.  Keep the advertised command ID so a
		 * reinitialized queue can explicitly start the same round.
		 */
		sc->vbsc_free_page_hint_active = false;
		pci_vtballoon_migration_abandon(sc);
	}
	return (0);
}

static int
pci_vtballoon_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtballoon_softc *sc;
	struct virtio_balloon_config config;

	sc = vsc;
	if (retval == NULL)
		return (EINVAL);
	*retval = 0;
	if (offset < 0 || (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > sizeof(config) ||
	    (size_t)size > sizeof(config) - (size_t)offset)
		return (EINVAL);
	memset(&config, 0, sizeof(config));
	config.num_pages = htole32(sc->vbsc_accounting.vba_target_pages);
	config.actual = htole32(sc->vbsc_accounting.vba_actual_pages);
	if ((sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT) != 0)
		config.free_page_hint_cmd_id =
		    htole32(sc->vbsc_free_page_hint_cmd_id);
	if ((sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_PAGE_POISON) != 0)
		config.poison_val = htole32(sc->vbsc_poison_val);
	return (vi_config_read_le(&config, sizeof(config), offset, size,
	    retval));
}

static int
pci_vtballoon_cfgwrite(void *vsc, int offset, int size, uint32_t value)
{
	struct pci_vtballoon_softc *sc;
	int error;

	sc = vsc;
	if (size != sizeof(uint32_t))
		return (EINVAL);
	if (offset == offsetof(struct virtio_balloon_config, actual)) {
		error = virtio_balloon_accounting_set_actual(
		    &sc->vbsc_accounting, value);
		if (error == 0)
			VIRTIO_PROBE_BALLOON_CONFIG(
			    sc->vbsc_vs.vs_vc->vc_name,
			    sc->vbsc_accounting.vba_target_pages, value);
		return (error);
	}
	if (offset == offsetof(struct virtio_balloon_config, poison_val) &&
	    (sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_PAGE_POISON) != 0 &&
	    (sc->vbsc_vs.vs_status &
	    VIRTIO_CONFIG_STATUS_DRIVER_OK) == 0) {
		sc->vbsc_poison_val = value;
		VIRTIO_PROBE_BALLOON_POISON(sc->vbsc_vs.vs_vc->vc_name, value);
		if (sc->vbsc_debug != 0)
			EPRINTLN("vtballoon: poison value=%#x", value);
		return (0);
	}
	return (EINVAL);
}

#ifdef BHYVE_SNAPSHOT
static bool
pci_vtballoon_bitmap_valid(const struct pci_vtballoon_softc *sc,
    const uint8_t *bitmap)
{
	uint64_t pages;
	unsigned int valid_bits;
	uint8_t invalid_mask;

	pages = sc->vbsc_lowmem_size / BHYVE_BALLOON_PAGE_SIZE +
	    sc->vbsc_highmem_size / BHYVE_BALLOON_PAGE_SIZE;
	if (pages == 0)
		return (sc->vbsc_tracker.vbpt_bitmap_size == 0);
	valid_bits = (unsigned int)(pages % 8);
	if (valid_bits == 0)
		return (true);
	invalid_mask = (uint8_t)~((1U << valid_bits) - 1U);
	return ((bitmap[sc->vbsc_tracker.vbpt_bitmap_size - 1] &
	    invalid_mask) == 0);
}

static bool
pci_vtballoon_host_page_complete(const uint8_t *bitmap,
    uint64_t first_page, uint64_t host_offset, size_t pages_per_host)
{
	uint64_t page;

	for (page = 0; page < pages_per_host; page++) {
		uint64_t index;

		index = first_page +
		    host_offset / BHYVE_BALLOON_PAGE_SIZE + page;
		if ((bitmap[index / 8] &
		    (uint8_t)(1U << (index % 8))) == 0)
			return (false);
	}
	return (true);
}

/*
 * Apply at most limit host-page transitions in deterministic address order.
 * The same iterator is used with the bitmaps reversed to undo exactly the
 * successful prefix after a later platform failure.
 */
static int
pci_vtballoon_transition_region(struct pci_vtballoon_softc *sc,
    const uint8_t *from, const uint8_t *to, uint64_t region_base,
    uint64_t region_size, uint64_t first_page, size_t limit, size_t *applied)
{
	uint64_t host_offset;
	size_t host_page_size, pages_per_host;
	bool from_complete, to_complete;
	int error;

	host_page_size = sc->vbsc_tracker.vbpt_host_page_size;
	pages_per_host = host_page_size / BHYVE_BALLOON_PAGE_SIZE;
	for (host_offset = 0; host_offset < region_size;
	    host_offset += host_page_size) {
		from_complete = pci_vtballoon_host_page_complete(from,
		    first_page, host_offset, pages_per_host);
		to_complete = pci_vtballoon_host_page_complete(to,
		    first_page, host_offset, pages_per_host);
		if (from_complete == to_complete)
			continue;
		if (*applied == limit)
			return (0);
		if (to_complete)
			error = vi_platform_discard_ram(&sc->vbsc_vs,
			    region_base + host_offset, host_page_size);
		else
			error = vi_platform_undiscard_ram(&sc->vbsc_vs,
			    region_base + host_offset, host_page_size);
		if (to_complete) {
			VIRTIO_PROBE_BALLOON_DISCARD(
			    sc->vbsc_vs.vs_vc->vc_name,
			    region_base + host_offset, host_page_size, error);
		} else {
			VIRTIO_PROBE_BALLOON_UNDISCARD(
			    sc->vbsc_vs.vs_vc->vc_name,
			    region_base + host_offset, host_page_size, error);
		}
		if (error != 0)
			return (error);
		(*applied)++;
	}
	return (0);
}

static int
pci_vtballoon_transition_bitmap(struct pci_vtballoon_softc *sc,
    const uint8_t *from, const uint8_t *to)
{
	uint64_t high_first_page;
	size_t applied, rolled_back;
	int error, rollback_error;

	applied = 0;
	high_first_page =
	    sc->vbsc_lowmem_size / BHYVE_BALLOON_PAGE_SIZE;
	error = pci_vtballoon_transition_region(sc, from, to, 0,
	    sc->vbsc_lowmem_size, 0, SIZE_MAX, &applied);
	if (error != 0)
		goto rollback;
	error = pci_vtballoon_transition_region(sc, from, to,
	    sc->vbsc_highmem_base, sc->vbsc_highmem_size, high_first_page,
	    SIZE_MAX, &applied);
	if (error == 0)
		return (0);

rollback:
	rolled_back = 0;
	rollback_error = pci_vtballoon_transition_region(sc, to, from, 0,
	    sc->vbsc_lowmem_size, 0, applied, &rolled_back);
	if (rollback_error == 0)
		rollback_error = pci_vtballoon_transition_region(sc, to, from,
		    sc->vbsc_highmem_base, sc->vbsc_highmem_size,
		    high_first_page, applied, &rolled_back);
	if (rollback_error != 0 || rolled_back != applied) {
		vi_snapshot_restore_incomplete(&sc->vbsc_vs);
		return (rollback_error != 0 ? rollback_error : EIO);
	}
	return (error);
}

static int
pci_vtballoon_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	struct pci_vtballoon_softc *sc;
	struct virtio_balloon_stats stats;
	struct vi_req stats_req;
	uint8_t *bitmap;
	uint64_t highmem_base, highmem_size, lowmem_size;
	uint64_t bitmap_size;
	uint32_t actual, flags, free_page_hint_cmd_id, magic, poison_val;
	uint32_t stats_entries, stats_ignored;
	uint32_t stats_req_idx, target, version;
	uint16_t stats_present, stats_req_completion_id;
	uint16_t stats_req_descriptor_count, stats_req_packed_head;
	uint8_t free_page_hint_active, stats_held, stats_req_packed_wrap;
	uint8_t stats_valid;
	bool stats_values_zero;
	int error;

	sc = vsc;
	bitmap = NULL;
	magic = VTBALLOON_SNAPSHOT_MAGIC;
	version = VTBALLOON_SNAPSHOT_VERSION;
	flags = 0;
	target = sc->vbsc_accounting.vba_target_pages;
	actual = sc->vbsc_accounting.vba_actual_pages;
	poison_val = sc->vbsc_poison_val;
	free_page_hint_cmd_id =
	    (sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT) != 0 ?
	    sc->vbsc_free_page_hint_cmd_id : VTBALLOON_CMD_ID_STOP;
	free_page_hint_active = sc->vbsc_free_page_hint_active;
	lowmem_size = sc->vbsc_lowmem_size;
	highmem_base = sc->vbsc_highmem_base;
	highmem_size = sc->vbsc_highmem_size;
	bitmap_size = sc->vbsc_tracker.vbpt_bitmap_size;
	stats = sc->vbsc_stats;
	stats_req = sc->vbsc_stats_req;
	stats_held = sc->vbsc_stats_held;
	stats_valid = sc->vbsc_stats_valid;
	stats_present = stats.vbs_present;
	stats_entries = (uint32_t)stats.vbs_entries;
	stats_ignored = (uint32_t)stats.vbs_ignored;
	stats_req_idx = stats_req.idx;
	stats_req_descriptor_count = stats_req.descriptor_count;
	stats_req_completion_id = stats_req.completion_id;
	stats_req_packed_head = stats_req.packed_head;
	stats_req_packed_wrap = stats_req.packed_wrap;

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	/*
	 * Do not interpret a version-specific layout until both parts of the
	 * wire-format discriminator have been accepted.  In particular, an
	 * unknown future version must fail as unsupported even when the input is
	 * only the eight-byte prefix; treating it as a current layout would turn
	 * that into a misleading truncation error.
	 */
	if (magic != VTBALLOON_SNAPSHOT_MAGIC ||
	    version != VTBALLOON_SNAPSHOT_VERSION) {
		error = ENOTSUP;
		goto done;
	}
	SNAPSHOT_LE32_OR_LEAVE(flags, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(target, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(actual, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(lowmem_size, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(highmem_base, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(highmem_size, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(bitmap_size, meta, error, done);
	if (bitmap_size != sc->vbsc_tracker.vbpt_bitmap_size) {
		error = EINVAL;
		goto done;
	}
	if (vm_snapshot_is_loading(meta) && bitmap_size != 0) {
		bitmap = malloc((size_t)bitmap_size);
		if (bitmap == NULL) {
			error = ENOMEM;
			goto done;
		}
	}
	if (bitmap_size != 0) {
		SNAPSHOT_BUF_OR_LEAVE(meta->op == VM_SNAPSHOT_SAVE ?
		    sc->vbsc_bitmap : bitmap, (size_t)bitmap_size,
		    meta, error, done);
	}
	SNAPSHOT_U8_OR_LEAVE(stats_held, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(stats_valid, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(stats_present, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(stats_entries, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(stats_ignored, meta, error, done);
	for (size_t i = 0; i < nitems(stats.vbs_value); i++)
		SNAPSHOT_LE64_OR_LEAVE(stats.vbs_value[i], meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(stats_req_idx, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(stats_req_descriptor_count, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(stats_req_completion_id, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(stats_req_packed_head, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(stats_req_packed_wrap, meta, error, done);
	SNAPSHOT_LE64_OR_LEAVE(stats_req.queue_generation, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(poison_val, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(free_page_hint_cmd_id, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(free_page_hint_active, meta, error, done);
	/*
	 * A retained statistics token is not queue ownership and cannot be
	 * reconstructed transactionally.  Checkpoint pause completes it before
	 * save, so fail closed on an out-of-contract image carrying ownership.
	 */
	if (stats_held != 0) {
		error = meta->op == VM_SNAPSHOT_SAVE ? EBUSY : ENOTSUP;
		goto done;
	}
	stats_values_zero = true;
	for (size_t i = 0; i < nitems(stats.vbs_value); i++)
		stats_values_zero &= stats.vbs_value[i] == 0;
	if (flags != 0 || lowmem_size != sc->vbsc_lowmem_size ||
	    highmem_base != sc->vbsc_highmem_base ||
	    highmem_size != sc->vbsc_highmem_size ||
	    target > sc->vbsc_accounting.vba_total_pages ||
	    actual > sc->vbsc_accounting.vba_total_pages ||
	    stats_held > 1 || stats_valid > 1 ||
	    stats_req_packed_wrap > 1 ||
	    (stats_present & ~((1U << BHYVE_BALLOON_STAT_COUNT) - 1U)) != 0 ||
	    stats_entries > BHYVE_BALLOON_STATS_MAX_ENTRIES ||
	    stats_ignored > stats_entries ||
	    (poison_val != 0 && (sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_PAGE_POISON) == 0) ||
	    (free_page_hint_cmd_id != VTBALLOON_CMD_ID_STOP &&
	    (sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT) == 0) ||
	    free_page_hint_active > 1 ||
	    (free_page_hint_active != 0 &&
	    (free_page_hint_cmd_id < VTBALLOON_CMD_ID_FIRST ||
	    (sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT) == 0)) ||
	    (stats_valid && (stats_entries == 0 ||
	    (sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_STATS_VQ) == 0)) ||
	    (!stats_valid && (stats_present != 0 || stats_entries != 0 ||
	    stats_ignored != 0 || !stats_values_zero)) ||
	    (!stats_held && (stats_req_idx != 0 ||
	    stats_req_descriptor_count != 0 ||
	    stats_req_completion_id != 0 || stats_req_packed_head != 0 ||
	    stats_req_packed_wrap != 0 || stats_req.queue_generation != 0)) ||
	    (stats_held && (!stats_valid ||
	    (sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_STATS_VQ) == 0))) {
		error = EINVAL;
		goto done;
	}
	stats.vbs_present = stats_present;
	stats.vbs_entries = stats_entries;
	stats.vbs_ignored = stats_ignored;
	stats_req.idx = stats_req_idx;
	stats_req.descriptor_count = stats_req_descriptor_count;
	stats_req.completion_id = stats_req_completion_id;
	stats_req.packed_head = stats_req_packed_head;
	stats_req.packed_wrap = stats_req_packed_wrap;
	stats_req.outstanding = stats_held != 0;
	if (stats_held && !pci_vtballoon_stats_req_valid(sc, &stats_req)) {
		error = EINVAL;
		goto done;
	}
	if (vm_snapshot_is_loading(meta)) {
		if (!pci_vtballoon_bitmap_valid(sc, bitmap)) {
			error = EINVAL;
			goto done;
		}
	}
	if (vm_snapshot_is_restoring(meta)) {
		error = pci_vtballoon_transition_bitmap(sc,
		    sc->vbsc_bitmap, bitmap);
		if (error != 0)
			goto done;
		sc->vbsc_accounting.vba_target_pages = target;
		sc->vbsc_accounting.vba_actual_pages = actual;
		sc->vbsc_stats = stats;
		sc->vbsc_stats_req = stats_req;
		sc->vbsc_stats_held = stats_held;
		sc->vbsc_stats_valid = stats_valid;
		sc->vbsc_free_page_hint_cmd_id = free_page_hint_cmd_id;
		sc->vbsc_free_page_hint_active =
		    free_page_hint_active != 0;
		sc->vbsc_poison_val = poison_val;
		if (sc->vbsc_tracker.vbpt_bitmap_size != 0) {
			memcpy(sc->vbsc_bitmap, bitmap,
			    sc->vbsc_tracker.vbpt_bitmap_size);
		}
	}
	error = 0;
done:
	free(bitmap);
	return (error);
}

/*
 * Validation reads accounting, page-tracker, retained-statistics, and
 * free-page-hint state which guest callbacks update under vbsc_mtx.  Unlike
 * commit-time pause, this direct preflight must not drain queues or change
 * guest memory; it only takes the local serializer around the common codec.
 */
static int
pci_vtballoon_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtballoon_softc *sc;
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);

	pthread_mutex_lock(&sc->vbsc_mtx);
	error = vi_pci_snapshot(meta);
	pthread_mutex_unlock(&sc->vbsc_mtx);
	return (error);
}
#endif

/* ------------------------------------------------------------------------- */
/* Migration free-page-hint bridge.                                          */
/* ------------------------------------------------------------------------- */

struct pci_vtballoon_softc *
virtio_balloon_migration_lookup(void)
{
	struct pci_vtballoon_softc *sc;

	pthread_mutex_lock(&pci_vtballoon_registry_lock);
	sc = pci_vtballoon_registry;
	pthread_mutex_unlock(&pci_vtballoon_registry_lock);
	return (sc);
}

static bool
pci_vtballoon_migration_supported(const struct pci_vtballoon_softc *sc)
{

	return ((sc->vbsc_vs.vs_negotiated_caps &
	    VIRTIO_BALLOON_F_FREE_PAGE_HINT) != 0 &&
	    (sc->vbsc_vs.vs_status & VIRTIO_CONFIG_STATUS_DRIVER_OK) != 0);
}

int
virtio_balloon_migration_start(struct pci_vtballoon_softc *sc,
    virtio_balloon_range_cb sink, void *arg)
{
	uint32_t cmd_id;
	int error;

	if (sc == NULL || sink == NULL)
		return (EINVAL);
	pthread_mutex_lock(&sc->vbsc_mtx);
	if (sc->vbsc_migration_round) {
		error = EBUSY;
		goto out;
	}
	if (!pci_vtballoon_migration_supported(sc)) {
		error = ENXIO;
		goto out;
	}
	/*
	 * Publish a fresh, monotonic command id at or above FIRST and distinct
	 * from the currently visible one, so the guest treats it as a new
	 * round.  Wrap back to FIRST on overflow.
	 */
	cmd_id = sc->vbsc_migration_next_cmd_id;
	if (cmd_id < VTBALLOON_CMD_ID_FIRST)
		cmd_id = VTBALLOON_CMD_ID_FIRST;
	if (cmd_id == sc->vbsc_free_page_hint_cmd_id)
		cmd_id = cmd_id >= UINT32_MAX ? VTBALLOON_CMD_ID_FIRST :
		    cmd_id + 1;
	sc->vbsc_migration_next_cmd_id = cmd_id >= UINT32_MAX ?
	    VTBALLOON_CMD_ID_FIRST : cmd_id + 1;
	sc->vbsc_migration_sink = sink;
	sc->vbsc_migration_sink_arg = arg;
	sc->vbsc_migration_round = true;
	sc->vbsc_migration_complete = false;
	sc->vbsc_free_page_hint_active = false;
	sc->vbsc_free_page_hint_cmd_id = cmd_id;
	VIRTIO_PROBE_BALLOON_HINT(sc->vbsc_vs.vs_vc->vc_name, "migrate-start",
	    cmd_id, UINT64_MAX, 0);
	vi_pci_config_changed(&sc->vbsc_vs);
	error = 0;
out:
	pthread_mutex_unlock(&sc->vbsc_mtx);
	return (error);
}

bool
virtio_balloon_migration_complete(struct pci_vtballoon_softc *sc)
{
	bool complete;

	if (sc == NULL)
		return (false);
	pthread_mutex_lock(&sc->vbsc_mtx);
	complete = sc->vbsc_migration_round && sc->vbsc_migration_complete;
	pthread_mutex_unlock(&sc->vbsc_mtx);
	return (complete);
}

int
virtio_balloon_migration_wait(struct pci_vtballoon_softc *sc,
    unsigned int timeout_ms)
{
	struct timespec deadline;
	int error, rc;

	if (sc == NULL)
		return (EINVAL);
	if (clock_gettime(CLOCK_REALTIME, &deadline) != 0)
		return (errno != 0 ? errno : EIO);
	deadline.tv_sec += (time_t)(timeout_ms / 1000U);
	deadline.tv_nsec += (long)(timeout_ms % 1000U) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec += 1;
		deadline.tv_nsec -= 1000000000L;
	}
	error = 0;
	pthread_mutex_lock(&sc->vbsc_mtx);
	while (sc->vbsc_migration_round && !sc->vbsc_migration_complete) {
		rc = pthread_cond_timedwait(&sc->vbsc_migration_cv,
		    &sc->vbsc_mtx, &deadline);
		if (rc != 0) {
			error = rc;
			break;
		}
	}
	if (error == 0 &&
	    !(sc->vbsc_migration_round && sc->vbsc_migration_complete))
		error = ECANCELED;
	pthread_mutex_unlock(&sc->vbsc_mtx);
	return (error);
}

void
virtio_balloon_migration_finish(struct pci_vtballoon_softc *sc)
{

	if (sc == NULL)
		return;
	pthread_mutex_lock(&sc->vbsc_mtx);
	if (sc->vbsc_migration_round) {
		sc->vbsc_migration_sink = NULL;
		sc->vbsc_migration_sink_arg = NULL;
		sc->vbsc_migration_round = false;
		sc->vbsc_migration_complete = false;
		sc->vbsc_free_page_hint_active = false;
		/* Release the guest from the round by publishing DONE. */
		sc->vbsc_free_page_hint_cmd_id = VTBALLOON_CMD_ID_DONE;
		VIRTIO_PROBE_BALLOON_HINT(sc->vbsc_vs.vs_vc->vc_name,
		    "migrate-finish", VTBALLOON_CMD_ID_DONE, UINT64_MAX, 0);
		vi_pci_config_changed(&sc->vbsc_vs);
		/*
		 * Now that DONE is published and the initial snapshot is
		 * complete, complete the retained STOP descriptor.  The guest's
		 * reporting thread unblocks and returns its reported pages to
		 * the allocator; any later write re-marks the page dirty and it
		 * is copied in a subsequent generation.
		 */
		if (sc->vbsc_migration_stop_held) {
			struct vqueue_info *vq =
			    &sc->vbsc_vq[VTBALLOON_FREE_PAGE_QUEUE];

			vq_relchain_req(vq, &sc->vbsc_migration_stop_req, 0);
			vq_endchains(vq, 1);
			sc->vbsc_migration_stop_held = false;
			memset(&sc->vbsc_migration_stop_req, 0,
			    sizeof(sc->vbsc_migration_stop_req));
		}
	}
	pthread_mutex_unlock(&sc->vbsc_mtx);
}

int
virtio_balloon_migration_collect(struct pci_vtballoon_softc *sc,
    virtio_balloon_range_cb sink, void *arg, unsigned int timeout_ms)
{
	int error;

	error = virtio_balloon_migration_start(sc, sink, arg);
	if (error != 0)
		return (error);
	error = virtio_balloon_migration_wait(sc, timeout_ms);
	virtio_balloon_migration_finish(sc);
	return (error);
}

static int
pci_vtballoon_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtballoon_softc *sc;
	const char *errstr, *value;
	uint64_t ram_bytes;
	size_t bitmap_size, target_bytes;
	long stats_interval;
	bool hinting, intr_initialized, mtx_initialized, packed, poison;
	bool reporting, stats;
	int error;

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (1);
	intr_initialized = false;
	mtx_initialized = false;
	if (pthread_mutex_init(&sc->vbsc_mtx, NULL) != 0)
		goto failed;
	mtx_initialized = true;
	if (pthread_cond_init(&sc->vbsc_migration_cv, NULL) != 0)
		goto failed;
	sc->vbsc_migration_cv_ready = true;
	sc->vbsc_migration_next_cmd_id = VTBALLOON_CMD_ID_FIRST;

	sc->vbsc_consts = vtballoon_vi_consts;
	value = getenv("BHYVE_VIRTIO_DEBUG");
	if (value != NULL) {
		char *end;
		unsigned long debug;

		errno = 0;
		debug = strtoul(value, &end, 10);
		if (errno == 0 && end != value && *end == '\0' &&
		    debug <= UINT_MAX)
			sc->vbsc_debug = (unsigned int)debug;
	}
	stats = false;
	hinting = get_config_bool_node_default(nvl,
	    "free_page_hinting", false);
	if (hinting) {
		sc->vbsc_consts.vc_nvq = VTBALLOON_FREE_PAGE_QUEUE + 1;
		sc->vbsc_consts.vc_hv_caps |=
		    VIRTIO_BALLOON_F_FREE_PAGE_HINT;
		sc->vbsc_free_page_hint_cmd_id = VTBALLOON_CMD_ID_FIRST;
	}
	poison = get_config_bool_node_default(nvl, "page_poison", false);
	if (poison)
		sc->vbsc_consts.vc_hv_caps |=
		    VIRTIO_BALLOON_F_PAGE_POISON;
	reporting = get_config_bool_node_default(nvl,
	    "free_page_reporting", false);
	if (reporting) {
		sc->vbsc_consts.vc_nvq = VTBALLOON_NVQ;
		sc->vbsc_consts.vc_hv_caps |=
		    VIRTIO_BALLOON_F_PAGE_REPORTING;
	}
	stats_interval = 0;
	if (get_config_bool_node_default(nvl, "deflate_on_oom", false))
		sc->vbsc_consts.vc_hv_caps |=
		    VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
	value = get_config_value_node(nvl, "stats_interval");
	if (value != NULL) {
		stats_interval = strtonum(value, VTBALLOON_STATS_INTERVAL_MIN,
		    VTBALLOON_STATS_INTERVAL_MAX, &errstr);
		if (errstr != NULL)
			goto failed;
		stats = true;
		if (!reporting &&
		    sc->vbsc_consts.vc_nvq < VTBALLOON_STATS_QUEUE + 1)
			sc->vbsc_consts.vc_nvq = VTBALLOON_STATS_QUEUE + 1;
		sc->vbsc_consts.vc_hv_caps |= VIRTIO_BALLOON_F_STATS_VQ;
	}
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed)
		sc->vbsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	vi_softc_linkup(&sc->vbsc_vs, &sc->vbsc_consts, sc, pi,
	    sc->vbsc_vq);
	sc->vbsc_vs.vs_mtx = &sc->vbsc_mtx;
	for (size_t i = 0; i < nitems(sc->vbsc_vq); i++)
		sc->vbsc_vq[i].vq_qsize = VTBALLOON_RINGSZ;
	/*
	 * Queue indices are fixed by the specification.  Reporting is queue 4,
	 * so advertising it raises num_queues to five.  Any intervening queue
	 * whose feature is not offered must still report QueueSize=0: otherwise
	 * the guest can discover an operational-looking statistics or
	 * free-page-hint queue without negotiating its defining feature.
	 */
	if (!stats)
		sc->vbsc_vq[VTBALLOON_STATS_QUEUE].vq_qsize = 0;
	if (!hinting)
		sc->vbsc_vq[VTBALLOON_FREE_PAGE_QUEUE].vq_qsize = 0;
	if (vi_pci_select_transport(&sc->vbsc_vs, nvl,
	    VIRTIO_PCI_MODERN_ONLY) != 0)
		goto failed;

	sc->vbsc_lowmem_size = vm_get_lowmem_size(pi->pi_vmctx);
	sc->vbsc_highmem_base = vm_get_highmem_base(pi->pi_vmctx);
	sc->vbsc_highmem_size = vm_get_highmem_size(pi->pi_vmctx);
	if (sc->vbsc_lowmem_size > UINT64_MAX - sc->vbsc_highmem_size)
		goto failed;
	ram_bytes = sc->vbsc_lowmem_size + sc->vbsc_highmem_size;
	target_bytes = 0;
	value = get_config_value_node(nvl, "target");
	if (value != NULL && (vm_parse_memsize(value, &target_bytes) != 0 ||
	    target_bytes % BHYVE_BALLOON_PAGE_SIZE != 0))
		goto failed;
	if (target_bytes / BHYVE_BALLOON_PAGE_SIZE > UINT32_MAX)
		goto failed;
	error = virtio_balloon_accounting_init(&sc->vbsc_accounting,
	    ram_bytes, (uint32_t)(target_bytes / BHYVE_BALLOON_PAGE_SIZE));
	if (error != 0)
		goto failed;
	error = virtio_balloon_tracker_required(sc->vbsc_lowmem_size,
	    sc->vbsc_highmem_base, sc->vbsc_highmem_size, &bitmap_size);
	if (error != 0)
		goto failed;
	sc->vbsc_bitmap = calloc(1, bitmap_size);
	if (bitmap_size != 0 && sc->vbsc_bitmap == NULL)
		goto failed;
	error = virtio_balloon_tracker_init(&sc->vbsc_tracker,
	    sc->vbsc_lowmem_size, sc->vbsc_highmem_base,
	    sc->vbsc_highmem_size,
	    vi_platform_ram_page_size(&sc->vbsc_vs), sc->vbsc_bitmap,
	    bitmap_size);
	if (error != 0)
		goto failed;

	vi_pci_modern_set_identity(&sc->vbsc_vs, VIRTIO_ID_BALLOON);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_MEMORY);
	if (vi_intr_init(&sc->vbsc_vs, 1, fbsdrun_virtio_msix()))
		goto failed;
	intr_initialized = true;
	if (vi_pci_modern_init(&sc->vbsc_vs, 2) != 0)
		goto failed;
	if (stats) {
		sc->vbsc_stats_evp = mevent_add((int)stats_interval * 1000,
		    EVF_TIMER, pci_vtballoon_stats_timer, sc);
		if (sc->vbsc_stats_evp == NULL)
			goto failed;
	}
	/*
	 * Publish this instance for the migration free-page-hint bridge.  A VM
	 * has at most one balloon device, so a last-writer-wins registration is
	 * sufficient and needs no per-device unregister on the process-lifetime
	 * device.
	 */
	pthread_mutex_lock(&pci_vtballoon_registry_lock);
	pci_vtballoon_registry = sc;
	pthread_mutex_unlock(&pci_vtballoon_registry_lock);
	return (0);

failed:
	if (sc->vbsc_stats_evp != NULL)
		/* The periodic callback retains sc until event retirement. */
		(void)mevent_delete_sync(sc->vbsc_stats_evp);
	free(sc->vbsc_bitmap);
	free(sc->vbsc_vs.vs_modern);
	if (intr_initialized)
		pthread_mutex_destroy(&sc->vbsc_vs.vs_isr_mtx);
	if (sc->vbsc_migration_cv_ready)
		pthread_cond_destroy(&sc->vbsc_migration_cv);
	if (mtx_initialized)
		pthread_mutex_destroy(&sc->vbsc_mtx);
	free(sc);
	return (1);
}

static const struct pci_devemu pci_de_vtballoon = {
	.pe_emu = "virtio-balloon",
	.pe_init = pci_vtballoon_init,
	.pe_cfgwrite = vi_pci_modern_cfgwrite,
	.pe_cfgread = vi_pci_modern_cfgread,
	.pe_barwrite = vi_pci_write,
	.pe_barread = vi_pci_read,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot = vi_pci_snapshot,
	.pe_snapshot_validate = pci_vtballoon_snapshot_validate,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause = vi_pci_pause,
	.pe_resume = vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vtballoon);
