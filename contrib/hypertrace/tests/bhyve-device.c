/* SPDX-License-Identifier: BSD-2-Clause */
#define WITHOUT_CAPSICUM
#include <stdatomic.h>
#include "pci_emul.h"
#undef PCI_EMUL_SET
#define PCI_EMUL_SET(x)
#include "pci_virtio_dtrace.c"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); abort(); } } while (0)

static void
init_monotonic_cond(pthread_cond_t *cond)
{
	pthread_condattr_t attr;

	CHECK(pthread_condattr_init(&attr) == 0);
	CHECK(pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0);
	CHECK(pthread_cond_init(cond, &attr) == 0);
	CHECK(pthread_condattr_destroy(&attr) == 0);
}

void vm_snapshot_buf_err(const char *name __unused,
    enum vm_snapshot_op op __unused) {}

int vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{
	if (meta->buffer.buf_rem < size)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else if (vm_snapshot_is_loading(meta))
		memcpy(data, meta->buffer.buf, size);
	else
		return (EINVAL);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (0);
}

static int
snapshot_scalar(uint64_t *value, size_t size, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[8] = { 0 };
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		for (size_t i = 0; i < size; i++)
			bytes[i] = (uint8_t)(*value >> (i * 8));
	error = vm_snapshot_buf(bytes, size, meta);
	if (error == 0 && vm_snapshot_is_loading(meta)) {
		*value = 0;
		for (size_t i = 0; i < size; i++)
			*value |= (uint64_t)bytes[i] << (i * 8);
	}
	return (error);
}

int vm_snapshot_u8(uint8_t *value, struct vm_snapshot_meta *meta)
{
	return (vm_snapshot_buf(value, sizeof(*value), meta));
}

int vm_snapshot_le16(uint16_t *value, struct vm_snapshot_meta *meta)
{
	uint64_t decoded = *value;
	int error = snapshot_scalar(&decoded, 2, meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = (uint16_t)decoded;
	return (error);
}

int vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint64_t decoded = *value;
	int error = snapshot_scalar(&decoded, 4, meta);
	if (error == 0 && vm_snapshot_is_loading(meta))
		*value = (uint32_t)decoded;
	return (error);
}

int vm_snapshot_le64(uint64_t *value, struct vm_snapshot_meta *meta)
{
	return (snapshot_scalar(value, 8, meta));
}

static int private_validate_stub;
int vi_pci_snapshot(struct vm_snapshot_meta *meta)
{
	if (private_validate_stub && meta->op == VM_SNAPSHOT_VALIDATE) {
		struct pci_devinst *pi = meta->dev_data;
		struct virtio_softc *vs = pi->pi_arg;
		int error = vs->vs_vc->vc_snapshot(pi->pi_arg, meta);
		return (error != 0 ? error :
		    private_validate_stub == 2 ? EPROTO : 0);
	}
	return (EOPNOTSUPP);
}
static int available, malformed, completions, write_error, split, writes,
    reset_calls;
static bool checkpoint_tx_pending;
static bool checkpoint_tx_use_available;
static int discarded_completions;
static bool checkpoint_tx_check_lock;
static int checkpoint_tx_error;
static const struct pci_vtdtr_control *incoming_controls;
static size_t incoming_index;
static uint64_t vm_epoch = 99;
static int init_fail_stage, status_error, status_grant,
    ingress_bad_digest, ingress_revoked, ingress_wrong_id, ingress_replay,
    ingress_phase,
    thread_fail_after = -1;
static int handoff_queries, handoff_kills, handoff_error, handoff_bad_id,
    handoff_empty_digest, handoff_binds, handoff_bind_fail_on,
    handoff_ingress_queries, handoff_live_queries, handoff_live_kills,
    rekey_applied_calls;
static uint8_t handoff_phase = 'a', handoff_revoked,
    handoff_kill_phase = 'a', handoff_kill_revoked = 1;
static uint8_t handoff_digest_7[32], handoff_digest_9[32];
static struct pci_vtdtr_control output;
static size_t dma_dirty_bytes;
static unsigned dma_dirty_marks;
static const struct pci_vtdtr_control *dma_expected;
static dtraced_hdr_t last_write;
static dtraced_hdr_t last_upload;
static uint8_t last_upload_digest[32];
static int last_upload_valid;
static dtraced_hdr_t injected_header;
static uint64_t injected_generation;
static atomic_int injected_frame;
extern int __real_pthread_create(pthread_t *, const pthread_attr_t *,
    void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start)(void *), void *arg)
{
	if (thread_fail_after == 0)
		return (EAGAIN);
	if (thread_fail_after > 0)
		thread_fail_after--;
	return (__real_pthread_create(thread, attr, start, arg));
}
static int hypertrace_ready = 1;
int hypertrace_initialized(void) { return (hypertrace_ready); }
static int session_gate_failure;
static uint8_t session_gate_owner[16];
static uint8_t destination_gate_owner[16];
static int destination_gate_failure;
static bool destination_released;
static int release_failure, release_calls;
static bool gate_noerrno;
int hypertrace_session_host_released(struct vmctx *ctx,
    const uint8_t token[16]) {
	CHECK(ctx == (struct vmctx *)1 && memcmp(token, destination_gate_owner, 16) == 0);
	if (destination_gate_failure || !destination_released) {
		errno = destination_gate_failure ?
		    (gate_noerrno ? 0 : destination_gate_failure) : EBUSY;
		return (-1);
	}
	return (0);
}
/* Optional state changes applied while the daemon call is in progress. */
static void (*release_hook)(struct pci_vtdtr_softc *);
static void (*collector_hook)(struct pci_vtdtr_softc *);
static bool retired_noerrno;
int hypertrace_session_release(struct vmctx *ctx, const uint8_t token[16]) {
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	CHECK(pthread_mutex_trylock(&sc->vsd_mtx) == 0);
	CHECK(sc->vsd_session_stop_requested && sc->vsd_fresh_active);
	if (release_hook != NULL)
		release_hook(sc);
	pthread_mutex_unlock(&sc->vsd_mtx);
	if (release_hook == NULL)
		CHECK(pci_vtdtr_session_authorize(ctx) == EBUSY);
	CHECK(memcmp(token, destination_gate_owner, 16) == 0);
	release_calls++;
	destination_released = true;
	if (release_failure) { errno = release_failure < 0 ? 0 : release_failure; return (-1); }
	return (0);
}
static bool source_retired;
static int collector_step_result, collector_step_error, collector_step_calls;
static bool collector_change_token, collector_gate_loss;
int hypertrace_session_collectors_stop_step(struct vmctx *ctx,
    const uint8_t token[16]) {
	struct pci_vtdtr_softc *sc = vtdtr_shutdown_sc;
	bool complete = true;
	CHECK(sc != NULL && ctx == sc->vsd_vmctx);
	CHECK(pthread_mutex_trylock(&sc->vsd_mtx) == 0);
	CHECK(memcmp(token, sc->vsd_session_gate_token, 16) == 0);
	if (collector_hook != NULL)
		collector_hook(sc);
	pthread_mutex_unlock(&sc->vsd_mtx);
	if (collector_hook == NULL)
		CHECK(pci_vtdtr_session_collectors_stop_step(ctx, &complete) == EBUSY && !complete);
	collector_step_calls++;
	if (collector_change_token)
		sc->vsd_session_stop_token ^= 1;
	if (collector_gate_loss)
		session_gate_failure = EBUSY;
	errno = collector_step_error;
	return (collector_step_result);
}
int hypertrace_session_retired(uint16_t vmid, uint64_t epoch) {
	CHECK(vmid != 0 && epoch != 0);
	if (!source_retired) { errno = retired_noerrno ? 0 : EBUSY; return (-1); }
	return (0);
}
int hypertrace_session_host_stop(struct vmctx *ctx,
    const uint8_t token[16]) {
	if (ctx == (struct vmctx *)1) {
		if (!destination_released && memcmp(destination_gate_owner, (const uint8_t[16]){0}, 16) != 0)
			CHECK(memcmp(destination_gate_owner, token, 16) == 0);
		memcpy(destination_gate_owner, token, 16);
		destination_released = false;
		if (destination_gate_failure) {
			errno = gate_noerrno ? 0 : destination_gate_failure;
			return (-1);
		}
		return (0);
	}
	if (memcmp(session_gate_owner, (const uint8_t[16]){0}, 16) != 0)
		CHECK(memcmp(session_gate_owner, token, 16) == 0);
	memcpy(session_gate_owner, token, 16);
	if (session_gate_failure != 0) {
		errno = gate_noerrno ? 0 : session_gate_failure;
		return (-1);
	}
	return (0);
}
int hypertrace_session_host_stopped(struct vmctx *ctx,
    const uint8_t token[16]) {
	if (ctx == (struct vmctx *)1) {
		CHECK(memcmp(destination_gate_owner, token, 16) == 0);
		if (destination_released) { errno = EBUSY; return (-1); }
		if (destination_gate_failure) {
			errno = gate_noerrno ? 0 : destination_gate_failure;
			return (-1);
		}
		return (0);
	}
	CHECK(memcmp(session_gate_owner, token, 16) == 0);
	if (session_gate_failure != 0) {
		errno = gate_noerrno ? 0 : session_gate_failure;
		return (-1);
	}
	return (0);
}
static dtraced_replay_kill_t admission_kills[2];
/* Optional scripted transport for reader tests (NULL: injected frame). */
static int (*read_epoch_script)(void **, dtraced_hdr_t *, uint64_t *, uint64_t *);
static int ack_epoch_error, ack_epoch_calls;
int hypertrace_read_epoch(void **buf, dtraced_hdr_t *hdr,
    uint64_t *generation, uint64_t *connection) {
    if (read_epoch_script != NULL)
        return (read_epoch_script(buf, hdr, generation, connection));
    if (atomic_exchange_explicit(&injected_frame, 0,
        memory_order_acquire) != 0) {
        *buf = NULL;
        *hdr = injected_header;
        *generation = injected_generation;
        *connection = 1;
        return (0);
    }
    errno = EAGAIN; return (-1); }
int hypertrace_ack_epoch(uint64_t epoch __unused,
    uint64_t connection __unused,
    uint64_t delivery_id __unused) {
	ack_epoch_calls++;
	if (ack_epoch_error != 0) { errno = ack_epoch_error; return (-1); }
	return (0);
}
int fbsdrun_virtio_msix(void) { return (0); }
void vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
    void *dev_softc __unused, struct pci_devinst *pi, struct vqueue_info *queues)
{
	int i;

	vs->vs_vc = vc; vs->vs_pi = pi; vs->vs_queues = queues; pi->pi_arg = vs;
	for (i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
		queues[i].vq_layout = VIRTIO_QUEUE_SPLIT;
	}
}
int vi_intr_init(struct virtio_softc *vs, int bar __unused, int msix __unused)
{
	if (init_fail_stage == 1) return (1);
	return (pthread_mutex_init(&vs->vs_isr_mtx, NULL));
}
void vi_set_io_bar(struct virtio_softc *vs __unused, int bar __unused) {}
static uint64_t transport_generation;
uint64_t hypertrace_reset(void) {
	reset_calls++;
	return (++transport_generation);
}
static uint16_t fake_vmid = 42;
uint16_t vm_get_vmid(struct vmctx *ctx __unused) { return (fake_vmid); }
/* Optional per-call identity script: each call consumes one entry (fail is
 * the errno to report, -1 for a failure without errno). */
struct identity_step { int fail; uint16_t vmid; uint64_t epoch; };
static const struct identity_step *identity_script;
static int identity_script_len, identity_calls;
int vm_get_identity(struct vmctx *ctx, uint16_t *id, uint64_t *epoch) {
    if (identity_script != NULL && identity_calls < identity_script_len) {
	const struct identity_step *step = &identity_script[identity_calls++];
	if (step->fail != 0) {
		errno = step->fail == -1 ? 0 : step->fail;
		return (-1);
	}
	*id = step->vmid;
	*epoch = step->epoch;
	return (0);
    }
    identity_calls++;
    *id = ctx == (struct vmctx *)1 ? 43 : 42;
    *epoch = ctx == (struct vmctx *)1 ? 100 : vm_epoch;
    return 0;
}
static const char *vm_name_override;
const char *vm_get_name(struct vmctx *ctx __unused) {
	return (vm_name_override != NULL ? vm_name_override : "test");
}
int hypertrace_write(const dtraced_hdr_t *header, void *payload,
    size_t size) {
	CHECK(header != NULL);
	last_write = *header;
	if (last_write.msg_type == DTRACED_MSG_ELF && write_error == 0) {
		struct hypertrace_vm_envelope envelope;
		size_t offset;
		CHECK(payload != NULL && last_write.elf.len == size &&
		    size >= HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4);
		hypertrace_envelope_decode(&envelope,
		    (const uint8_t *)payload);
		offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
		    envelope.name_length;
		CHECK(offset + 4 <= size &&
		    SHA256((const uint8_t *)payload + offset, size - offset,
		    last_upload_digest) != NULL);
		last_upload = last_write;
		last_upload_valid = 1;
	}
	writes++; errno = write_error; return (write_error != 0 ? -1 : 0);
}
int hypertrace_delivery_status(const dtraced_hdr_t *request,
    dtraced_delivery_status_t *status) {
	CHECK(request->msg_type == DTRACED_MSG_STATUS);
	last_write = *request;
	if (status_error != 0) { errno = status_error; return (-1); }
	status->delivery_id = request->installed.delivery_id;
	status->phase = 'i';
	status->revoked = status_grant ? 0 : 1;
	status->replay = status_grant;
	if (status_grant) status->digest[0] = 0x42;
	return (0);
}
int hypertrace_ingress_status(const dtraced_hdr_t *request,
    dtraced_delivery_status_t *status) {
	CHECK(request->msg_type == DTRACED_MSG_INGRESS_STATUS);
	last_write = *request;
	if (status_error != 0) { errno = status_error; return (-1); }
	status->delivery_id = request->installed.delivery_id;
	status->phase = 'a';
	if (last_upload_valid &&
	    request->installed.delivery_id == last_upload.elf.delivery_id &&
	    memcmp(request->installed.program_id,
	    last_upload.elf.program_id, 16) == 0 &&
	    memcmp(request->installed.source_id,
	    last_upload.elf.source_id, 16) == 0)
		memcpy(status->digest, last_upload_digest, 32);
	else
		status->digest[0] = 0x42;
	if (ingress_bad_digest)
		status->digest[0] ^= 1;
	status->revoked = ingress_revoked;
	if (ingress_wrong_id)
		status->delivery_id ^= 1;
	if (ingress_phase != 0)
		status->phase = ingress_phase;
	status->replay = ingress_replay;
	return (0);
}
int hypertrace_handoff_delivery_prestart(struct vmctx *ctx,
    const dtraced_handoff_delivery_request_t *request,
    dtraced_delivery_status_t *status) {
	CHECK(ctx != NULL && request->token[0] == 0xa1 &&
	    request->digest[0] == 0xb2 &&
	    (request->scope == 0 || request->scope == 3) &&
	    request->program_id[0] == 1 && request->source_id[0] == 2);
	handoff_queries++;
	if (request->scope == 3)
		handoff_ingress_queries++;
	if (handoff_error != 0) { errno = handoff_error; return (-1); }
	memset(status, 0, sizeof(*status));
	status->delivery_id = request->delivery_id + handoff_bad_id;
	status->phase = request->scope == 3 ? 'a' : handoff_phase;
	status->revoked = handoff_revoked;
	if (!handoff_empty_digest) {
		if (request->scope == 0 && request->delivery_id == 7)
			memcpy(status->digest, handoff_digest_7, 32);
		else if (request->scope == 0 && request->delivery_id == 9)
			memcpy(status->digest, handoff_digest_9, 32);
		else
			status->digest[0] = 0x42;
	}
	return (0);
}
int hypertrace_handoff_bind_delivery_prestart(struct vmctx *ctx,
    const dtraced_handoff_bind_delivery_request_t *request,
    dtraced_delivery_status_t *status) {
	CHECK(request->delivery.scope == 0 &&
	    memcmp(request->payload_digest, (const uint8_t[32]){0}, 32) != 0);
	handoff_binds++;
	if (handoff_bind_fail_on == handoff_binds) {
		errno = ETIMEDOUT;
		return (-1);
	}
	return (hypertrace_handoff_delivery_prestart(ctx, &request->delivery,
	    status));
}
int hypertrace_handoff_delivery_live(struct vmctx *ctx,
    const dtraced_handoff_delivery_request_t *request,
    dtraced_delivery_status_t *status) {
	handoff_live_queries++;
	return (hypertrace_handoff_delivery_prestart(ctx, request, status));
}
int hypertrace_handoff_kill_prestart(struct vmctx *ctx,
    const dtraced_handoff_kill_request_t *request,
    dtraced_delivery_status_t *status) {
	CHECK(ctx != NULL && request->token[0] == 0xa1 &&
	    request->digest[0] == 0xb2 && request->pid == 3 &&
	    (request->source_id[0] == 2 || request->source_id[0] == 0x55));
	handoff_kills++;
	if (handoff_error != 0) { errno = handoff_error; return (-1); }
	memset(status, 0, sizeof(*status));
	status->delivery_id = (uint32_t)request->pid + handoff_bad_id;
	status->phase = handoff_kill_phase;
	status->revoked = handoff_kill_revoked;
	return (0);
}
int hypertrace_handoff_kill_live(struct vmctx *ctx,
    const dtraced_handoff_kill_request_t *request,
    dtraced_delivery_status_t *status) {
	handoff_live_kills++;
	return (hypertrace_handoff_kill_prestart(ctx, request, status));
}
int hypertrace_handoff_cleanup_prestart(struct vmctx *ctx,
    const dtraced_handoff_cleanup_request_t *request,
    dtraced_delivery_status_t *status) {
	CHECK(ctx != NULL && request->token[0] == 0xa1 &&
	    request->digest[0] == 0xb2 && request->delivery_id != 0);
	if (handoff_error != 0) { errno = handoff_error; return (-1); }
	memset(status, 0, sizeof(*status));
	status->delivery_id = request->delivery_id + handoff_bad_id;
	status->phase = handoff_phase;
	return (0);
}
int hypertrace_handoff_rekey_applied(struct vmctx *ctx,
    const uint8_t token[16], const uint8_t digest[32])
{
	CHECK(ctx != NULL && token[0] == 0xa1 && digest[0] == 0xb2);
	rekey_applied_calls++;
	return (0);
}
static uint32_t *delivered_log;
static size_t delivered_count, delivered_cap;
static void locked(struct virtio_softc *vs)
{
	CHECK(pthread_mutex_trylock(vs->vs_mtx) == EBUSY);
}
int vq_has_descs(struct vqueue_info *vq)
{
	locked(vq->vq_vs);
	return (available > 0);
}
int vq_checkpoint_has_descs(struct vqueue_info *vq, bool *pending)
{
	CHECK(vq->vq_num == 1);
	if (checkpoint_tx_check_lock)
		locked(vq->vq_vs);
	*pending = checkpoint_tx_use_available ? available > 0 : checkpoint_tx_pending;
	return (checkpoint_tx_error);
}
/* Chain-shape faults: a getchain error, or a malformed request shape
 * (unordered chain, extra readable/writable counts, too many segments). */
static int chain_error, chain_zero, chain_unordered, chain_readable_delta,
    chain_writable_delta, chain_niov_over;
static int
chain_shape(struct vi_req *req, int n)
{
	if (chain_unordered) req->ordered = false;
	req->readable += chain_readable_delta;
	req->writable += chain_writable_delta;
	return (chain_niov_over ? VTDTR_MAX_IOV + 1 : n);
}
int vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
    struct vi_req *req)
{
	locked(vq->vq_vs);
	CHECK(niov == VTDTR_MAX_IOV);
	if (chain_error) { chain_error = 0; return (-1); }
	if (chain_zero) { chain_zero = 0; return (0); }
	if (available == 0) return (0);
	available--;
	memset(req, 0, sizeof(*req));
	req->ordered = true;
	if (incoming_controls != NULL) {
		req->readable = 1;
		iov->iov_base = __DECONST(void *,
		    &incoming_controls[incoming_index++]);
		iov->iov_len = sizeof(struct pci_vtdtr_control);
		return (chain_shape(req, 1));
	}
	req->writable = split ? (split == 3 ? 4 : 2) : 1;
	iov->iov_base = &output;
	iov->iov_len = malformed ? 1 : sizeof(output);
	if (split == 3) {
		static uint8_t spare[8];
		iov[0].iov_len = 7;
		iov[1].iov_base = (char *)&output + 7;
		iov[1].iov_len = 0;
		iov[2].iov_base = (char *)&output + 7;
		iov[2].iov_len = sizeof(output) - 7;
		iov[3].iov_base = spare;
		iov[3].iov_len = sizeof(spare);
		return (chain_shape(req, 4));
	}
	if (split) {
		iov[0].iov_len = 7;
		iov[1].iov_base = (char *)&output + 7;
		iov[1].iov_len = sizeof(output) - 7;
	}
	return (chain_shape(req, split ? 2 : 1));
}
void vi_mark_dma_dirty(struct virtio_softc *vs, void *mapping, size_t len)
{
	locked(vs);
	CHECK((uintptr_t)mapping >= (uintptr_t)&output &&
	    (uintptr_t)mapping + len <= (uintptr_t)&output + sizeof(output));
	if (dma_expected != NULL)
		CHECK(memcmp(&output, dma_expected, sizeof(output)) == 0);
	dma_dirty_bytes += len;
	dma_dirty_marks++;
}
void vq_relchain_req(struct vqueue_info *vq, struct vi_req *req __unused,
    uint32_t length)
{
	locked(vq->vq_vs);
	if (length != 0) completions++;
	else discarded_completions++;
	/* Optional record of delivered control events, in order. */
	if (length != 0 && delivered_log != NULL && delivered_count < delivered_cap)
		delivered_log[delivered_count++] = output.pvc_event;
}
void vq_endchains(struct vqueue_info *vq, int all __unused) { locked(vq->vq_vs); }
void vi_set_needs_reset(struct virtio_softc *vs)
{
	locked(vs);
	vs->vs_status |= VIRTIO_CONFIG_S_NEEDS_RESET;
}
void vi_reset_dev(struct virtio_softc *vs)
{
	locked(vs);
	vs->vs_status = 0;
}
static void test_init_failures(void)
{
	struct pci_devinst pi = { 0 };
	for (int stage = 1; stage <= 3; stage++) {
		init_fail_stage = stage;
		thread_fail_after = stage == 2 ? 0 : stage == 3 ? 1 : -1;
		CHECK(pci_vtdtr_init(&pi, NULL) != 0);
		CHECK(pi.pi_arg == NULL && !vtdtr_present);
	}
	init_fail_stage = 0;
	thread_fail_after = -1;
}

static void
test_restore_kill_reserve(void)
{
	struct pci_vtdtr_ctrlq queue = { 0 }, pending = { 0 };
	struct pci_vtdtr_ctrl_entry kill = { .restored_kill = true };

	STAILQ_INIT(&queue.head);
	STAILQ_INIT(&pending.head);
	CHECK(VTDTR_MAX_RESTORE_PENDING ==
	    VTDTR_MAX_PENDING + DTRACED_REPLAY_KILL_MAX);
	queue.count = VTDTR_MAX_PENDING - 3;
	CHECK(pci_vtdtr_replay_manifest_room(&queue,
	    DTRACED_REPLAY_KILL_MAX));
	queue.count++;
	CHECK(!pci_vtdtr_replay_manifest_room(&queue,
	    DTRACED_REPLAY_KILL_MAX));
	queue.count = VTDTR_MAX_PENDING - 3;
	CHECK(!pci_vtdtr_replay_manifest_room(&queue,
	    DTRACED_REPLAY_KILL_MAX + 1));
	queue.restored_kills = queue.count + 1;
	CHECK(!pci_vtdtr_replay_manifest_room(&queue, 0));
	queue.restored_kills = 0;
	queue.count = VTDTR_MAX_RESTORE_PENDING - 4;
	queue.restored_kills = DTRACED_REPLAY_KILL_MAX;
	pending.count = 1;
	CHECK(pci_vtdtr_publish_room(&queue, &pending));
	queue.count++;
	CHECK(!pci_vtdtr_publish_room(&queue, &pending));
	queue.count = VTDTR_MAX_PENDING - 3;
	queue.restored_kills = 0;
	pending.count = 3;
	CHECK(!pci_vtdtr_publish_room(&queue, &pending));
	queue.count = VTDTR_MAX_PENDING;
	CHECK(!pci_vtdtr_normal_control_room(&queue));
	queue.restored_kills = 1;
	CHECK(pci_vtdtr_normal_control_room(&queue));
	queue.count = VTDTR_MAX_RESTORE_PENDING;
	queue.restored_kills = DTRACED_REPLAY_KILL_MAX;
	CHECK(!pci_vtdtr_normal_control_room(&queue));
	queue.count = 0;
	queue.restored_kills = 0;
	pending.count = 0;
	pci_vtdtr_cq_enqueue(&queue, &kill);
	CHECK(queue.count == 1 && queue.restored_kills == 1 &&
	    pci_vtdtr_cq_dequeue(&queue) == &kill &&
	    queue.count == 0 && queue.restored_kills == 0);
}

static int
validate_private_image(uint8_t *image, size_t length, size_t *remaining)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = length,
			.buf = image,
			.buf_rem = length,
		},
		.op = VM_SNAPSHOT_VALIDATE,
	};
	int error = pci_vtdtr_private_snapshot(NULL, &meta);
	if (remaining != NULL)
		*remaining = meta.buffer.buf_rem;
	return (error);
}

static int
stage_private_image(uint8_t *image, size_t length,
    struct pci_vtdtr_checkpoint_stage *stage)
{
	struct vm_snapshot_meta meta = {
		.buffer = {
			.buf_start = image,
			.buf_size = length,
			.buf = image,
			.buf_rem = length,
		},
		.op = VM_SNAPSHOT_VALIDATE,
	};
	return (pci_vtdtr_private_snapshot_stage(NULL, &meta, stage));
}

static void
test_private_image(void)
{
	struct pci_vtdtr_softc sc = { 0 };
	struct pci_vtdtr_ctrlq queue = { 0 };
	struct pci_vtdtr_control ctrl = { .pvc_event = VTDTR_DEVICE_KILL };
	struct pci_vtdtr_ctrl_entry entry = { .ctrl = &ctrl };
	uint8_t image[8192] = { 0 };
	uint8_t token[16] = { 0xa1 }, digest[32] = { 0xb2 };
	struct pci_vtdtr_checkpoint_stage staged = { 0 };
	size_t length, remaining, control_offset;
	struct vm_snapshot_meta save = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};

	STAILQ_INIT(&queue.head);
	queue.count = 0;
	sc.vsd_ctrlq = &queue;
	sc.vsd_vs.vs_negotiated_caps = VTDTR_RESTORE_REQUIRED_FEATURES;
	sc.vsd_vs.vs_mtx = &sc.vsd_mtx;
	sc.vsd_queues[1].vq_vs = &sc.vsd_vs;
	sc.vsd_queues[1].vq_num = 1;
	sc.vsd_cfg = 0x123456789abcdef0ULL;
	sc.vsd_guest_ready = 1;
	sc.vsd_ready = 1;
	CHECK(pthread_mutex_init(&sc.vsd_mtx, NULL) == 0);
	init_monotonic_cond(&sc.vsd_cond);
	ctrl.pvc_pid = 3;
	ctrl.pvc_kill_vmid = 42;
	ctrl.pvc_kill_epoch = 99;
	ctrl.pvc_source_id[0] = 0x55;
	pci_vtdtr_cq_enqueue(&queue, &entry);
	sc.vsd_inbound_elf.data = malloc(8);
	CHECK(sc.vsd_inbound_elf.data != NULL);
	memset(sc.vsd_inbound_elf.data, 0x7c, 4);
	sc.vsd_inbound_elf.total = 8;
	sc.vsd_inbound_elf.received = 4;
	sc.vsd_inbound_elf.identifier = 6;
	sc.vsd_inbound_delivery_id = 7;
	sc.vsd_inbound_vmid = 42;
	sc.vsd_inbound_epoch = 99;
	sc.vsd_inbound_program_id[0] = 1;
	sc.vsd_inbound_source_id[0] = 2;
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EOPNOTSUPP);
	CHECK(pci_vtdtr_snapshot(&sc, &save) == EOPNOTSUPP &&
	    save.buffer.buf_rem == sizeof(image));
	CHECK(pci_vtdtr_private_snapshot(&sc, &save) == 0);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	length = sizeof(image) - save.buffer.buf_rem;
	CHECK(length > 34 && memcmp(image, "VDR1", 4) == 0);
	CHECK(validate_private_image(image, length, &remaining) == 0 &&
	    remaining == 0);
	/* The generic validator must expose only the private bytes it parsed,
	 * and only while the device is paused for restore preflight. */
	struct pci_devemu capture_dev = {
	    .pe_emu = "virtio-dtrace",
	    .pe_snapshot_validate = pci_vtdtr_snapshot_validate,
	};
	struct pci_devinst capture_pi = {
	    .pi_arg = &sc,
	    .pi_d = &capture_dev,
	};
	const void *captured = NULL;
	size_t captured_length = 0;
	bool capture_complete = false;
	struct vm_snapshot_meta capture = {
	    .dev_data = &capture_pi,
	    .buffer = {
		.buf_start = image,
		.buf_size = length,
		.buf = image,
		.buf_rem = length,
	    },
	    .op = VM_SNAPSHOT_VALIDATE,
	};
	sc.vsd_vs.vs_vc = &vtdtr_vi_consts;
	CHECK(pci_vtdtr_checkpoint_is_device(&capture_pi));
	CHECK(pci_vtdtr_checkpoint_capture_begin(&capture_pi) == EBUSY);
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_checkpoint_source_replay_room(&capture_pi, 0) == 0);
	CHECK(pci_vtdtr_checkpoint_source_replay_room(&capture_pi,
	    VTDTR_MAX_PENDING - 5) == 0);
	CHECK(pci_vtdtr_checkpoint_source_replay_room(&capture_pi,
	    VTDTR_MAX_PENDING - 4) == ENOBUFS);
	CHECK(pci_vtdtr_checkpoint_source_replay_room(&capture_pi,
	    SIZE_MAX) == ENOBUFS);
	CHECK(pci_vtdtr_checkpoint_capture_begin(&capture_pi) == 0);
	private_validate_stub = 1;
	CHECK(pci_vtdtr_snapshot_validate(&capture) == EOPNOTSUPP);
	private_validate_stub = 0;
	CHECK(pci_vtdtr_checkpoint_capture_end(&capture_pi, &captured,
	    &captured_length, &capture_complete) == 0 && capture_complete &&
	    captured == image && captured_length == length &&
	    capture.buffer.buf_rem == 0);
	/* A private decode alone cannot open the gate if common VirtIO
	 * validation subsequently fails. */
	capture.buffer.buf = image;
	capture.buffer.buf_rem = length;
	CHECK(pci_vtdtr_checkpoint_capture_begin(&capture_pi) == 0);
	private_validate_stub = 2;
	CHECK(pci_vtdtr_snapshot_validate(&capture) == EPROTO);
	private_validate_stub = 0;
	CHECK(pci_vtdtr_checkpoint_capture_end(&capture_pi, &captured,
	    &captured_length, &capture_complete) == 0 && !capture_complete);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	CHECK(pci_vtdtr_checkpoint_private_image_query(image, length,
	    (struct vmctx *)1, token, digest) == EOPNOTSUPP);
	CHECK(pci_vtdtr_checkpoint_private_image_bind(image, length,
	    (struct vmctx *)1, token, digest) == EOPNOTSUPP &&
	    handoff_binds == 0);
	CHECK(pci_vtdtr_checkpoint_private_image_query(image, length + 1,
	    (struct vmctx *)1, token, digest) == EPROTO);
	CHECK(stage_private_image(image, length, &staged) == 0);
	CHECK(staged.source_vmid == 42 && staged.source_epoch == 99 &&
	    staged.cfg == sc.vsd_cfg && staged.guest_ready == 1 &&
	    staged.ready == 1 && staged.count == 1 &&
	    staged.controls[0].pvc_event == VTDTR_DEVICE_KILL &&
	    staged.controls[0].pvc_pid == 3 &&
	    staged.partial_total == 8 && staged.partial_received == 4 &&
	    staged.partial_prefix[0] == 0x7c);
	struct pci_vtdtr_ctrlq *planned = NULL;
	CHECK(pci_vtdtr_checkpoint_queue_plan(&staged, 43, 100,
	    &planned) == EOPNOTSUPP && planned == NULL);
	CHECK(stage_private_image(image, length, &staged) == EINVAL);
	pci_vtdtr_checkpoint_stage_clear(&staged);
	CHECK(staged.controls == NULL && staged.partial_prefix == NULL &&
	    staged.source_vmid == 0);
	CHECK(validate_private_image(image, length - 1, NULL) == E2BIG);
	CHECK(stage_private_image(image, length - 1, &staged) == E2BIG &&
	    staged.controls == NULL && staged.partial_prefix == NULL);
	/* A forged extra control fails the stream scan before staging any
	 * queue objects, even though its count fits the cheap 4-byte bound. */
	image[26] = 2;
	CHECK(stage_private_image(image, length, &staged) == E2BIG &&
	    staged.controls == NULL && staged.partial_prefix == NULL);
	image[26] = 1;
	image[4] = VTDTR_SNAPSHOT_VERSION - 1;
	CHECK(validate_private_image(image, length, NULL) == EPROTO);
	image[4] = VTDTR_SNAPSHOT_VERSION;
	control_offset = length - 34;
	CHECK(image[control_offset] == VTDTR_DEVICE_KILL);
	image[control_offset] = 0xff;
	CHECK(validate_private_image(image, length, NULL) == EINVAL);
	image[control_offset] = VTDTR_DEVICE_KILL;
	image[control_offset + 4] = 1;
	CHECK(validate_private_image(image, length, NULL) == EPROTO);
	CHECK(stage_private_image(image, length, &staged) == EPROTO &&
	    staged.controls == NULL && staged.partial_prefix == NULL);
	memset(&ctrl, 0, sizeof(ctrl));
	ctrl.pvc_event = VTDTR_DEVICE_ELF;
	ctrl.pvc_identifier = 5;
	ctrl.pvc_delivery_id = 9;
	ctrl.pvc_vmid = 42;
	ctrl.pvc_epoch = 99;
	ctrl.pvc_totalelflen = 4;
	ctrl.pvc_elflen = 4;
	ctrl.pvc_elfhasmore = 0;
	ctrl.pvc_program_id[0] = 1;
	ctrl.pvc_elf_source_id[0] = 2;
	memcpy(ctrl.pvc_elf, "\177ELF", 4);
	struct vm_snapshot_meta elf_save = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_private_snapshot(&sc, &elf_save) == 0);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	length = sizeof(image) - elf_save.buffer.buf_rem;
	CHECK(validate_private_image(image, length, &remaining) == 0 &&
	    remaining == 0);
	CHECK(stage_private_image(image, length, &staged) == 0 &&
	    staged.controls[0].pvc_event == VTDTR_DEVICE_ELF &&
	    staged.controls[0].pvc_elflen == 4 &&
	    memcmp(staged.controls[0].pvc_elf, "\177ELF", 4) == 0);
	pci_vtdtr_checkpoint_stage_clear(&staged);
	control_offset = length - 71;
	CHECK(image[control_offset] == VTDTR_DEVICE_ELF);
	image[control_offset + 34] = 1;
	CHECK(validate_private_image(image, length, NULL) == EPROTO);
	CHECK(stage_private_image(image, length, &staged) == EPROTO &&
	    staged.controls == NULL && staged.partial_prefix == NULL);
	image[control_offset + 34] = 0;
	image[control_offset + 4] = 1;
	image[control_offset + 5] = 8;
	CHECK(validate_private_image(image, length, NULL) == EINVAL);
	image[control_offset + 4] = 4;
	image[control_offset + 5] = 0;
	image[control_offset + 24] = 41;
	CHECK(validate_private_image(image, length, NULL) == EPROTO);
	memset(&ctrl, 0, sizeof(ctrl));
	ctrl.pvc_event = VTDTR_DEVICE_NODE_REKEY;
	ctrl.pvc_rekey_old_id = 41;
	ctrl.pvc_rekey_old_epoch = 98;
	ctrl.pvc_rekey_new_id = 42;
	ctrl.pvc_rekey_new_epoch = 99;
	struct vm_snapshot_meta rekey_save = {
		.buffer = {
			.buf_start = image,
			.buf_size = sizeof(image),
			.buf = image,
			.buf_rem = sizeof(image),
		},
		.op = VM_SNAPSHOT_SAVE,
	};
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EOPNOTSUPP);
	CHECK(pci_vtdtr_snapshot(&sc, &rekey_save) == EOPNOTSUPP &&
	    rekey_save.buffer.buf_rem == sizeof(image));
	CHECK(pci_vtdtr_private_snapshot(&sc, &rekey_save) == 0);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	length = sizeof(image) - rekey_save.buffer.buf_rem;
	CHECK(validate_private_image(image, length, &remaining) == 0 &&
	    remaining == 0);
	CHECK(stage_private_image(image, length, &staged) == 0 &&
	    staged.controls[0].pvc_event == VTDTR_DEVICE_NODE_REKEY &&
	    staged.controls[0].pvc_rekey_old_id == 41 &&
	    staged.controls[0].pvc_rekey_new_id == 42 &&
	    staged.controls[0].pvc_rekey_new_epoch == 99);
	pci_vtdtr_checkpoint_stage_clear(&staged);
	CHECK(pci_vtdtr_cq_dequeue(&queue) == &entry);
	hypertrace_elf_reset(&sc.vsd_inbound_elf);
	sc.vsd_inbound_delivery_id = 0;
	sc.vsd_inbound_vmid = 0;
	sc.vsd_inbound_epoch = 0;
	memset(sc.vsd_inbound_program_id, 0,
	    sizeof(sc.vsd_inbound_program_id));
	memset(sc.vsd_inbound_source_id, 0,
	    sizeof(sc.vsd_inbound_source_id));
	memset(&ctrl, 0, sizeof(ctrl));
	ctrl.pvc_event = VTDTR_DEVICE_ELF;
	ctrl.pvc_delivery_id = 9;
	ctrl.pvc_vmid = 42;
	ctrl.pvc_epoch = 99;
	ctrl.pvc_totalelflen = PCI_VTDTR_MAXELFLEN + 4;
	ctrl.pvc_elflen = 4;
	ctrl.pvc_program_id[0] = 1;
	ctrl.pvc_elf_source_id[0] = 2;
	pci_vtdtr_cq_enqueue(&queue, &entry);
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EOPNOTSUPP);
	ctrl.pvc_totalelflen = 4;
	sc.vsd_vs.vs_negotiated_caps &= ~VTDTR_WIRE_F_REKEY_RECEIPT_V1;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EPROTO);
	save.buffer.buf = image;
	save.buffer.buf_rem = sizeof(image);
	CHECK(pci_vtdtr_snapshot(&sc, &save) == EPROTO &&
	    save.buffer.buf_rem == sizeof(image));
	sc.vsd_vs.vs_negotiated_caps = VTDTR_RESTORE_REQUIRED_FEATURES;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == 0);
	sc.vsd_restore_planned = &queue;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EBUSY);
	sc.vsd_restore_planned = NULL;
	sc.vsd_ticket_wait = true;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EBUSY);
	sc.vsd_ticket_wait = false;
	sc.vsd_handoff_ticket_valid = true;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EBUSY);
	sc.vsd_handoff_ticket_valid = false;
	sc.vsd_rekey_ack_pending = true;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EBUSY);
	sc.vsd_rekey_ack_pending = false;
	sc.vsd_rekey_ack_sent = true;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EBUSY);
	sc.vsd_rekey_ack_sent = false;
	sc.vsd_rekey_receipt_reply_pending = true;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EBUSY);
	sc.vsd_rekey_receipt_reply_pending = false;
	sc.vsd_cleanup_unapplied = true;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EBUSY);
	sc.vsd_cleanup_unapplied = false;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == 0);
	CHECK(pci_vtdtr_pause(&sc) == 0);
	checkpoint_tx_check_lock = true;
	checkpoint_tx_pending = true;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EBUSY);
	save.buffer.buf = image;
	save.buffer.buf_rem = sizeof(image);
	CHECK(pci_vtdtr_snapshot(&sc, &save) == EBUSY &&
	    save.buffer.buf_rem == sizeof(image));
	checkpoint_tx_pending = false;
	checkpoint_tx_error = EFAULT;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EFAULT);
	checkpoint_tx_error = 0;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == 0);
	checkpoint_tx_check_lock = false;
	CHECK(pci_vtdtr_resume(&sc) == 0);
	ctrl.pvc_totalelflen = PCI_VTDTR_MAXELFLEN + 4;
	save.buffer.buf = image;
	save.buffer.buf_rem = sizeof(image);
	CHECK(pci_vtdtr_snapshot(&sc, &save) == EOPNOTSUPP &&
	    save.buffer.buf_rem == sizeof(image));
	CHECK(pci_vtdtr_cq_dequeue(&queue) == &entry);
	memset(&ctrl, 0, sizeof(ctrl));
	ctrl.pvc_event = VTDTR_DEVICE_CLEANUP_DTRACED;
	ctrl.pvc_cleanup_vmid = 42;
	ctrl.pvc_cleanup_epoch = 99;
	ctrl.pvc_cleanup_delivery_id = 456;
	pci_vtdtr_cq_enqueue(&queue, &entry);
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == 0);
	ctrl.pvc_cleanup_delivery_id = 0;
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == EPROTO);
	ctrl.pvc_cleanup_delivery_id = 456;
	save.buffer.buf = image;
	save.buffer.buf_rem = sizeof(image);
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_private_snapshot(&sc, &save) == 0);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	length = sizeof(image) - save.buffer.buf_rem;
	CHECK(validate_private_image(image, length, NULL) == 0);
	CHECK(stage_private_image(image, length, &staged) == 0 &&
	    staged.count == 1 &&
	    staged.controls[0].pvc_event == VTDTR_DEVICE_CLEANUP_DTRACED &&
	    staged.controls[0].pvc_cleanup_delivery_id == 456);
	CHECK(pci_vtdtr_checkpoint_private_image_replay_room(image,
	    length, VTDTR_MAX_PENDING - 5) == 0);
	CHECK(pci_vtdtr_checkpoint_private_image_replay_room(image,
	    length, VTDTR_MAX_PENDING - 4) == ENOBUFS);
	CHECK(pci_vtdtr_checkpoint_private_image_replay_room(image,
	    length, SIZE_MAX) == ENOBUFS);
	CHECK(pci_vtdtr_checkpoint_private_image_replay_room(image,
	    length + 1, 0) == EPROTO);
	CHECK(pci_vtdtr_checkpoint_private_image_query(image, length,
	    (struct vmctx *)1, token, digest) == 0);
	handoff_phase = 0;
	CHECK(pci_vtdtr_checkpoint_private_image_query(image, length,
	    (struct vmctx *)1, token, digest) == EPROTO);
	handoff_phase = 'a';
	handoff_bad_id = 1;
	CHECK(pci_vtdtr_checkpoint_private_image_query(image, length,
	    (struct vmctx *)1, token, digest) == EPROTO);
	handoff_bad_id = 0;
	struct pci_vtdtr_ctrlq *cleanup_plan = NULL;
	CHECK(pci_vtdtr_checkpoint_queue_plan(&staged, 43, 100,
	    &cleanup_plan) == 0 && cleanup_plan != NULL &&
	    cleanup_plan->count == 2);
	struct pci_vtdtr_ctrl_entry *cleanup_head =
	    STAILQ_FIRST(&cleanup_plan->head);
	CHECK(cleanup_head != NULL &&
	    cleanup_head->ctrl->pvc_event == VTDTR_DEVICE_NODE_REKEY);
	struct pci_vtdtr_ctrl_entry *cleanup_saved =
	    STAILQ_NEXT(cleanup_head, entries);
	CHECK(cleanup_saved != NULL &&
	    cleanup_saved->ctrl->pvc_event == VTDTR_DEVICE_CLEANUP_DTRACED &&
	    cleanup_saved->ctrl->pvc_cleanup_vmid == 43 &&
	    cleanup_saved->ctrl->pvc_cleanup_epoch == 100 &&
	    cleanup_saved->ctrl->pvc_cleanup_delivery_id == 456);
	pci_vtdtr_checkpoint_queue_free(cleanup_plan);
	pci_vtdtr_checkpoint_stage_clear(&staged);
	CHECK(pci_vtdtr_cq_dequeue(&queue) == &entry);
	memset(&ctrl, 0, sizeof(ctrl));
	ctrl.pvc_event = VTDTR_DEVICE_HOST_ELF;
	ctrl.pvc_installed_delivery_id = 8;
	ctrl.pvc_installed_vmid = 42;
	ctrl.pvc_installed_epoch = 99;
	ctrl.pvc_installed_program_id[0] = 1;
	ctrl.pvc_installed_source_id[0] = 2;
	ctrl.pvc_installed_digest[0] = 0x42;
	pci_vtdtr_cq_enqueue(&queue, &entry);
	save.buffer.buf = image;
	save.buffer.buf_rem = sizeof(image);
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_checkpoint_replayable(&sc) == 0);
	CHECK(pci_vtdtr_private_snapshot(&sc, &save) == 0);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	length = sizeof(image) - save.buffer.buf_rem;
	CHECK(pci_vtdtr_checkpoint_private_image_query(image, length,
	    (struct vmctx *)1, token, digest) == 0);
	int before_ingress = handoff_ingress_queries;
	CHECK(pci_vtdtr_checkpoint_private_image_bind(image, length,
	    (struct vmctx *)1, token, digest) == 0 && handoff_binds == 0 &&
	    handoff_ingress_queries == before_ingress + 1);
	CHECK(pci_vtdtr_checkpoint_private_image_query(image, length + 1,
	    (struct vmctx *)1, token, digest) == EPROTO);
	/* Restore plans the private image behind the paused device gate. The
	 * live queue changes only after the coordinator publishes the plan. */
	struct pci_vtdtr_softc restored = { 0 };
	struct pci_vtdtr_ctrlq *old_queue = calloc(1, sizeof(*old_queue));
	struct vm_snapshot_meta restore = {
		.buffer = {
			.buf_start = image,
			.buf_size = length,
			.buf = image,
			.buf_rem = length,
		},
		.op = VM_SNAPSHOT_RESTORE,
	};
	CHECK(old_queue != NULL);
	STAILQ_INIT(&old_queue->head);
	restored.vsd_ctrlq = old_queue;
	restored.vsd_vmctx = (struct vmctx *)1;
	restored.vsd_guest_ready = 1;
	restored.vsd_ready = 1;
	restored.vsd_vs.vs_mtx = &restored.vsd_mtx;
	restored.vsd_queues[1].vq_vs = &restored.vsd_vs;
	restored.vsd_queues[1].vq_num = 1;
	CHECK(pthread_mutex_init(&restored.vsd_mtx, NULL) == 0);
	init_monotonic_cond(&restored.vsd_cond);
	CHECK(pci_vtdtr_private_snapshot_restore(&restored, NULL) == EBUSY);
	CHECK(pci_vtdtr_snapshot(&restored, &restore) == EBUSY &&
	    restored.vsd_ctrlq == old_queue && restore.buffer.buf_rem == length);
	CHECK(pci_vtdtr_pause(&restored) == 0);
	restored.vsd_inbound_elf.total = 8;
	CHECK(pci_vtdtr_snapshot(&restored, &restore) == EPROTO &&
	    restored.vsd_ctrlq == old_queue && restore.buffer.buf_rem == length);
	restored.vsd_inbound_elf.total = 0;
	restored.vsd_ticket_wait = true;
	CHECK(pci_vtdtr_snapshot(&restored, &restore) == EBUSY &&
	    restored.vsd_ctrlq == old_queue && restore.buffer.buf_rem == length);
	restored.vsd_ticket_wait = false;
	image[0] ^= 1;
	CHECK(pci_vtdtr_snapshot(&restored, &restore) != 0 &&
	    restored.vsd_ctrlq == old_queue && restore.buffer.buf_rem == length);
	image[0] ^= 1;
	CHECK(pci_vtdtr_snapshot(&restored, &restore) == 0 &&
	    restore.buffer.buf_rem == 0 && restored.vsd_ctrlq == old_queue &&
	    restored.vsd_restore_planned != NULL &&
	    restored.vsd_guest_ready && restored.vsd_ready);
	CHECK(pci_vtdtr_private_snapshot_restore(&restored, &restore) == EBUSY &&
	    restored.vsd_ctrlq == old_queue &&
	    restored.vsd_restore_planned != NULL);
	CHECK(pci_vtdtr_resume(&restored) == EBUSY &&
	    restored.vsd_checkpoint_paused);
	restored.vsd_vs.vs_negotiated_caps = VTDTR_RESTORE_REQUIRED_FEATURES;
	restored.vsd_vmctx = (struct vmctx *)2;
	CHECK(pci_vtdtr_checkpoint_publish_sc_paused(&restored) == ESTALE &&
	    restored.vsd_ctrlq == old_queue &&
	    restored.vsd_restore_planned != NULL);
	restored.vsd_vmctx = (struct vmctx *)1;
	restored.vsd_vs.vs_negotiated_caps = 0;
	CHECK(pci_vtdtr_checkpoint_publish_sc_paused(&restored) == EPROTO &&
	    restored.vsd_ctrlq == old_queue &&
	    restored.vsd_restore_planned != NULL);
	restored.vsd_vs.vs_negotiated_caps =
	    VTDTR_RESTORE_REQUIRED_FEATURES &
	    ~VTDTR_WIRE_F_REKEY_RECEIPT_V1;
	CHECK(pci_vtdtr_checkpoint_publish_sc_paused(&restored) == EPROTO &&
	    restored.vsd_ctrlq == old_queue &&
	    restored.vsd_restore_planned != NULL);
	restored.vsd_vs.vs_negotiated_caps = VTDTR_RESTORE_REQUIRED_FEATURES;
	CHECK(pci_vtdtr_checkpoint_publish_sc_paused(&restored) == EACCES &&
	    restored.vsd_ctrlq == old_queue && old_queue->count == 0 &&
	    restored.vsd_restore_planned != NULL &&
	    !restored.vsd_handoff_ticket_valid);
	struct pci_devemu restore_emu = {
	    .pe_emu = "virtio-dtrace",
	    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
	struct pci_devinst restore_pi = {
	    .pi_d = &restore_emu, .pi_arg = &restored };
	dtraced_replay_kill_t admission_kill = {
	    .pid = 7, .vmid = 43, .epoch = 100,
	    .source_id = { 0x33 } };
	admission_kill.epoch++;
	CHECK(pci_vtdtr_handoff_ticket_attach_paused(&restore_pi,
	    token, digest, &admission_kill, 1) == ESTALE &&
	    restored.vsd_ctrlq == old_queue && old_queue->count == 0 &&
	    restored.vsd_restore_planned->count == 2 &&
	    !restored.vsd_handoff_ticket_valid);
	admission_kill.epoch--;
	CHECK(pci_vtdtr_handoff_ticket_attach_paused(&restore_pi,
	    token, digest, &admission_kill, 1) == 0 &&
	    restored.vsd_ctrlq == old_queue && old_queue->count == 0 &&
	    restored.vsd_restore_planned->count == 3 &&
	    restored.vsd_handoff_ticket_valid);
	checkpoint_tx_check_lock = true;
	checkpoint_tx_pending = true;
	CHECK(pci_vtdtr_checkpoint_publish_sc_paused(&restored) == EBUSY &&
	    restored.vsd_ctrlq == old_queue &&
	    restored.vsd_restore_planned != NULL);
	checkpoint_tx_pending = false;
	checkpoint_tx_error = EFAULT;
	CHECK(pci_vtdtr_checkpoint_publish_sc_paused(&restored) == EFAULT &&
	    restored.vsd_ctrlq == old_queue &&
	    restored.vsd_restore_planned != NULL);
	checkpoint_tx_error = 0;
	int publish_error = pci_vtdtr_checkpoint_publish_sc_paused(&restored);
	checkpoint_tx_check_lock = false;
	CHECK(publish_error == 0 &&
	    restored.vsd_ctrlq != old_queue &&
	    restored.vsd_restore_planned == NULL &&
	    restored.vsd_cfg == sc.vsd_cfg && !restored.vsd_guest_ready &&
	    !restored.vsd_ready && restored.vsd_handoff_ticket_valid &&
	    restored.vsd_ctrlq->count == 3);
	struct pci_vtdtr_ctrl_entry *restored_head =
	    STAILQ_FIRST(&restored.vsd_ctrlq->head);
	CHECK(restored_head != NULL &&
	    restored_head->ctrl->pvc_event == VTDTR_DEVICE_NODE_REKEY &&
	    restored_head->ctrl->pvc_rekey_old_id == 42 &&
	    restored_head->ctrl->pvc_rekey_old_epoch == 99 &&
	    restored_head->ctrl->pvc_rekey_new_id == 43 &&
	    restored_head->ctrl->pvc_rekey_new_epoch == 100);
	struct pci_vtdtr_ctrl_entry *restored_kill =
	    STAILQ_NEXT(restored_head, entries);
	CHECK(restored_kill != NULL && restored_kill->restored_kill &&
	    restored_kill->ctrl->pvc_event == VTDTR_DEVICE_KILL &&
	    restored_kill->ctrl->pvc_pid == 7 &&
	    STAILQ_NEXT(restored_kill, entries) != NULL);
	CHECK(!pci_vtdtr_rekey_head_awaits_ticket(&restored));
	CHECK(pci_vtdtr_resume(&restored) == 0);
	pci_vtdtr_checkpoint_queue_free(restored.vsd_ctrlq);
	CHECK(pthread_cond_destroy(&restored.vsd_cond) == 0);
	CHECK(pthread_mutex_destroy(&restored.vsd_mtx) == 0);
	CHECK(pci_vtdtr_cq_dequeue(&queue) == &entry);
	CHECK(pthread_cond_destroy(&sc.vsd_cond) == 0);
	CHECK(pthread_mutex_destroy(&sc.vsd_mtx) == 0);
}

static void
test_checkpoint_stage_query(void)
{
	struct pci_vtdtr_control controls[4] = { 0 };
	struct pci_vtdtr_checkpoint_stage stage = {
		.controls = controls, .count = 2,
		.source_vmid = 42, .source_epoch = 99,
	};
	uint8_t token[16] = { 0xa1 }, digest[32] = { 0xb2 };
	struct vmctx *ctx = (struct vmctx *)1;
	int before_receipt_query;

	controls[0].pvc_event = VTDTR_DEVICE_ELF;
	controls[0].pvc_vmid = 42;
	controls[0].pvc_epoch = 99;
	controls[0].pvc_delivery_id = 7;
	controls[0].pvc_program_id[0] = 1;
	controls[0].pvc_elf_source_id[0] = 2;
	controls[0].pvc_totalelflen = PCI_VTDTR_MAXELFLEN + 4;
	controls[0].pvc_elflen = PCI_VTDTR_MAXELFLEN;
	controls[0].pvc_elfhasmore = 1;
	controls[1] = controls[0];
	controls[1].pvc_elflen = 4;
	controls[1].pvc_elfhasmore = 0;
	uint8_t zero_payload[PCI_VTDTR_MAXELFLEN + 4] = { 0 };
	unsigned digest_length = 0;
	CHECK(EVP_Digest(zero_payload, sizeof(zero_payload),
	    handoff_digest_7, &digest_length, EVP_sha256(), NULL) == 1 &&
	    digest_length == 32);
	CHECK(EVP_Digest(zero_payload, 4, handoff_digest_9,
	    &digest_length, EVP_sha256(), NULL) == 1 &&
	    digest_length == 32);
	handoff_queries = handoff_kills = 0;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == 0 && handoff_queries == 1);
	controls[1].pvc_elf[0] = 1;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	controls[1].pvc_elf[0] = 0;
	controls[0].pvc_elflen = 4;
	controls[0].pvc_elfhasmore = 0;
	stage.count = 1;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EOPNOTSUPP);
	stage.count = 2;
	controls[0].pvc_elflen = PCI_VTDTR_MAXELFLEN;
	controls[0].pvc_elfhasmore = 1;
	handoff_phase = 'p';
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	handoff_phase = 'a';
	handoff_revoked = 1;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	handoff_revoked = 0;
	handoff_bad_id = 1;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	handoff_bad_id = 0;
	handoff_empty_digest = 1;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	handoff_empty_digest = 0;
	handoff_error = ETIMEDOUT;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == ETIMEDOUT);
	handoff_error = 0;
	controls[1].pvc_delivery_id = 8;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	controls[1].pvc_delivery_id = 7;
	/* A second complete ELF with the same delivery ID is a new run,
	 * not a continuation that can skip its own receipt digest. */
	controls[2] = controls[1];
	controls[2].pvc_totalelflen = 4;
	controls[2].pvc_elflen = 4;
	stage.count = 3;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	memset(&controls[2], 0, sizeof(controls[2]));
	controls[2].pvc_event = VTDTR_DEVICE_KILL;
	controls[2].pvc_pid = 3;
	controls[2].pvc_kill_vmid = 42;
	controls[2].pvc_kill_epoch = 99;
	controls[2].pvc_source_id[0] = 2;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == 0 && handoff_kills == 1);
	struct pci_vtdtr_ctrlq *planned = NULL;
	CHECK(pci_vtdtr_checkpoint_queue_plan(&stage, 42, 99,
	    &planned) == EINVAL && planned == NULL);
	CHECK(pci_vtdtr_checkpoint_queue_plan(&stage, 43, 100,
	    &planned) == 0 && planned->count == 4);
	struct pci_vtdtr_ctrl_entry *item = STAILQ_FIRST(&planned->head);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_NODE_REKEY &&
	    item->ctrl->pvc_rekey_old_id == 42 &&
	    item->ctrl->pvc_rekey_new_id == 43 && !item->restored_kill);
	item = STAILQ_NEXT(item, entries);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_KILL &&
	    item->ctrl->pvc_kill_vmid == 43 &&
	    item->ctrl->pvc_kill_epoch == 100 && item->restored_kill);
	item = STAILQ_NEXT(item, entries);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_ELF &&
	    item->ctrl->pvc_vmid == 43 && item->ctrl->pvc_epoch == 100 &&
	    !item->restored_kill);
	item = STAILQ_NEXT(item, entries);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_ELF &&
	    item->ctrl->pvc_elfhasmore == 0);
	/* A revocation replayed after the image cut must follow NODE_REKEY
	 * and earlier saved KILLs, but must not trail saved ELF fragments. */
	struct pci_vtdtr_softc restored = { 0 };
	struct pci_vtdtr_ctrlq pending = { 0 };
	STAILQ_INIT(&pending.head);
	restored.vsd_ctrlq = planned;
	CHECK(pthread_mutex_init(&restored.vsd_mtx, NULL) == 0);
	init_monotonic_cond(&restored.vsd_cond);
	for (pid_t pid = 4; pid <= 5; pid++) {
		struct pci_vtdtr_ctrl_entry *late = calloc(1, sizeof(*late));
		CHECK(late != NULL);
		late->ctrl = calloc(1, sizeof(*late->ctrl));
		CHECK(late->ctrl != NULL);
		late->ctrl->pvc_event = VTDTR_DEVICE_KILL;
		late->ctrl->pvc_pid = pid;
		late->ctrl->pvc_kill_vmid = 43;
		late->ctrl->pvc_kill_epoch = 100;
		late->ctrl->pvc_source_id[0] = (uint8_t)pid;
		pci_vtdtr_cq_enqueue(&pending, late);
		CHECK(pci_vtdtr_publish(&restored, &pending, 0, false));
	}
	CHECK(planned->count == 6);
	item = STAILQ_FIRST(&planned->head);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_NODE_REKEY);
	item = STAILQ_NEXT(item, entries);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_KILL &&
	    item->ctrl->pvc_pid == 3 && item->restored_kill);
	for (pid_t pid = 4; pid <= 5; pid++) {
		item = STAILQ_NEXT(item, entries);
		CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_KILL &&
		    item->ctrl->pvc_pid == pid && item->restored_kill &&
		    item->restored_control);
	}
	item = STAILQ_NEXT(item, entries);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_ELF &&
	    item->restored_elf_start);
	/* Once the first fragment was sent, another late KILL must not be
	 * inserted into the remainder of that ELF run. */
	for (unsigned i = 0; i < 5; i++) {
		item = pci_vtdtr_cq_dequeue(planned);
		CHECK(item != NULL);
		free(item->ctrl);
		free(item);
	}
	item = STAILQ_FIRST(&planned->head);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_ELF &&
	    !item->restored_elf_start);
	struct pci_vtdtr_ctrl_entry *late = calloc(1, sizeof(*late));
	CHECK(late != NULL);
	late->ctrl = calloc(1, sizeof(*late->ctrl));
	CHECK(late->ctrl != NULL);
	late->ctrl->pvc_event = VTDTR_DEVICE_KILL;
	late->ctrl->pvc_pid = 6;
	pci_vtdtr_cq_enqueue(&pending, late);
	CHECK(pci_vtdtr_publish(&restored, &pending, 0, false) &&
	    planned->count == 2);
	item = STAILQ_NEXT(item, entries);
	CHECK(item == late && item->restored_kill &&
	    item->restored_control);
	CHECK(pthread_cond_destroy(&restored.vsd_cond) == 0);
	CHECK(pthread_mutex_destroy(&restored.vsd_mtx) == 0);
	pci_vtdtr_checkpoint_queue_free(planned);
	planned = NULL;
	handoff_kill_revoked = 0;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	handoff_kill_revoked = 1;
	handoff_kill_phase = 'p';
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == 0);
	controls[2].pvc_event = VTDTR_DEVICE_HOST_KILL_APPLIED;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	handoff_kill_phase = 'a';
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == 0);
	CHECK(pci_vtdtr_checkpoint_queue_plan(&stage, 43, 100,
	    &planned) == 0 && planned->count == 3);
	pci_vtdtr_checkpoint_queue_free(planned);
	planned = NULL;
	memset(&controls[2], 0, sizeof(controls[2]));
	controls[2].pvc_event = VTDTR_DEVICE_HOST_ELF;
	controls[2].pvc_installed_delivery_id = 8;
	controls[2].pvc_installed_vmid = 42;
	controls[2].pvc_installed_epoch = 99;
	controls[2].pvc_installed_program_id[0] = 1;
	controls[2].pvc_installed_source_id[0] = 2;
	controls[2].pvc_installed_digest[0] = 0x42;
	before_receipt_query = handoff_queries;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == 0 && handoff_queries == before_receipt_query + 2 &&
	    handoff_ingress_queries > 0);
	CHECK(pci_vtdtr_checkpoint_queue_plan(&stage, 43, 100,
	    &planned) == 0 && planned->count == 4);
	item = STAILQ_FIRST(&planned->head);
	while (STAILQ_NEXT(item, entries) != NULL)
		item = STAILQ_NEXT(item, entries);
	CHECK(item->ctrl->pvc_event == VTDTR_DEVICE_HOST_ELF &&
	    item->ctrl->pvc_installed_vmid == 43 &&
	    item->ctrl->pvc_installed_epoch == 100);
	pci_vtdtr_checkpoint_queue_free(planned);
	planned = NULL;
	stage.count = 4;
	controls[3].pvc_event = VTDTR_DEVICE_READY;
	CHECK(pci_vtdtr_checkpoint_queue_plan(&stage, 43, 100,
	    &planned) == 0 && planned->count == 4);
	pci_vtdtr_checkpoint_queue_free(planned);
	planned = NULL;
	controls[3].pvc_event = VTDTR_DEVICE_EOF;
	CHECK(pci_vtdtr_checkpoint_queue_plan(&stage, 43, 100,
	    &planned) == 0 && planned->count == 4);
	pci_vtdtr_checkpoint_queue_free(planned);
	planned = NULL;
	stage.count = 3;
	controls[2].pvc_installed_digest[0] = 0x43;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EPROTO);
	controls[2].pvc_installed_digest[0] = 0x42;
	controls[3] = controls[0];
	controls[3].pvc_delivery_id = 9;
	controls[3].pvc_totalelflen = 4;
	controls[3].pvc_elflen = 4;
	controls[3].pvc_elfhasmore = 0;
	stage.count = 4;
	handoff_binds = 0;
	handoff_bind_fail_on = 2;
	CHECK(pci_vtdtr_checkpoint_stage_bind(&stage, ctx, token,
	    digest) == ETIMEDOUT && handoff_binds == 2);
	handoff_bind_fail_on = 0;
	CHECK(pci_vtdtr_checkpoint_stage_bind(&stage, ctx, token,
	    digest) == 0 && handoff_binds == 4);
	controls[2].pvc_event = VTDTR_DEVICE_NODE_ID;
	controls[2].pvc_node_id = 42;
	controls[2].pvc_node_epoch = 99;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EOPNOTSUPP);
	CHECK(pci_vtdtr_checkpoint_stage_query(NULL, ctx, token,
	    digest) == EINVAL);
	token[0] = 0;
	CHECK(pci_vtdtr_checkpoint_stage_query(&stage, ctx, token,
	    digest) == EINVAL);
	handoff_revoked = 0;
}

static void
test_checkpoint_receipt_validation(void)
{
	struct pci_vtdtr_control ctrl = {
	    .pvc_event = VTDTR_DEVICE_HOST_STATUS,
	    .pvc_installed_delivery_id = 17,
	    .pvc_installed_vmid = 42,
	    .pvc_installed_epoch = 99,
	    .pvc_installed_query_id = 3,
	};
	ctrl.pvc_installed_program_id[0] = 1;
	ctrl.pvc_installed_source_id[0] = 2;
	CHECK(pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_replay = 1;
	CHECK(!pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_phase = 'a';
	ctrl.pvc_installed_digest[0] = 0x42;
	CHECK(pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_revoked = 1;
	CHECK(!pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_revoked = 0;
	ctrl.pvc_installed_phase = 'u';
	CHECK(!pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_replay = 0;
	ctrl.pvc_installed_digest[0] = 0;
	CHECK(pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_event = VTDTR_DEVICE_HOST_INGRESS_STATUS;
	ctrl.pvc_installed_phase = 'a';
	ctrl.pvc_installed_digest[0] = 0x42;
	CHECK(pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_digest[0] = 0;
	CHECK(!pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_phase = 'u';
	CHECK(pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_phase = 'i';
	CHECK(!pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_event = VTDTR_DEVICE_HOST_ELF;
	ctrl.pvc_installed_phase = 0;
	ctrl.pvc_installed_query_id = 0;
	CHECK(!pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_digest[0] = 0x42;
	CHECK(pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
	ctrl.pvc_installed_query_id = 3;
	CHECK(!pci_vtdtr_ctrl_checkpoint_valid(&ctrl, 42, 99));
}

static void *
finish_checkpoint_reader(void *arg)
{
	struct pci_vtdtr_softc *sc = arg;

	CHECK(pthread_mutex_lock(&sc->vsd_mtx) == 0);
	while (!sc->vsd_checkpoint_paused)
		CHECK(pthread_cond_wait(&sc->vsd_cond, &sc->vsd_mtx) == 0);
	CHECK(sc->vsd_reader_active);
	sc->vsd_reader_active = false;
	CHECK(pthread_cond_broadcast(&sc->vsd_cond) == 0);
	CHECK(pthread_mutex_unlock(&sc->vsd_mtx) == 0);
	return (NULL);
}

static void
test_reader_pause(void)
{
	struct pci_vtdtr_softc sc = { 0 };
	struct pci_vtdtr_ctrlq queue = { 0 };
	pthread_t reader;

	STAILQ_INIT(&queue.head);
	queue.count = 0;
	sc.vsd_ctrlq = &queue;
	sc.vsd_reader_active = true;
	CHECK(pthread_mutex_init(&sc.vsd_mtx, NULL) == 0);
	init_monotonic_cond(&sc.vsd_cond);
	CHECK(pthread_create(&reader, NULL, finish_checkpoint_reader,
	    &sc) == 0);
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(sc.vsd_checkpoint_paused && !sc.vsd_reader_active);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	CHECK(!sc.vsd_checkpoint_paused);
	CHECK(pthread_join(reader, NULL) == 0);
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_release_checkpoint_for_stop(&sc) == 0);
	CHECK(sc.vsd_stopping && sc.vsd_checkpoint_paused);
	CHECK(pthread_mutex_trylock(&sc.vsd_mtx) == 0);
	CHECK(pthread_mutex_unlock(&sc.vsd_mtx) == 0);
	CHECK(pthread_cond_destroy(&sc.vsd_cond) == 0);
	CHECK(pthread_mutex_destroy(&sc.vsd_mtx) == 0);
}
static void
test_fresh_private_restore(uint8_t *image, size_t length, const uint8_t *record,
    bool migration)
{
	memset(destination_gate_owner, 0, 16);
	destination_gate_failure = 0;
	destination_released = false;
	struct pci_vtdtr_softc dst = {0};
	struct pci_vtdtr_ctrlq queue = {0};
	struct pci_devemu emu = {.pe_emu = "virtio-dtrace",
	    .pe_snapshot_validate = pci_vtdtr_snapshot_validate};
	struct pci_devinst pi = {.pi_d = &emu, .pi_arg = &dst};
	STAILQ_INIT(&queue.head);
	dst.vsd_ctrlq = &queue;
	dst.vsd_vmctx = (struct vmctx *)1;
	dst.vsd_vs.vs_pi = &pi;
	dst.vsd_vs.vs_negotiated_caps = HYPERTRACE_SESSION_FEATURES;
	CHECK(pthread_mutex_init(&dst.vsd_mtx, NULL) == 0);
	init_monotonic_cond(&dst.vsd_cond);
	pthread_mutex_lock(&dst.vsd_mtx);
	CHECK(pci_vtdtr_session_restore_stage_paused(&pi, record, 40, image, length) == EBUSY);
	dst.vsd_checkpoint_paused = true;
	source_retired = false;
	CHECK(pci_vtdtr_session_restore_stage_paused(&pi, record, 40, image, length) == EBUSY);
	source_retired = true;
	image[24] = 1; /* A runnable guest image is not a fresh stopped cut. */
	CHECK(pci_vtdtr_session_restore_stage_paused(&pi, record, 40, image, length) == EPROTO);
	image[24] = 0;
	CHECK(!dst.vsd_session_restore_staged);
	destination_gate_failure = EIO;
	CHECK(pci_vtdtr_session_restore_stage_paused(&pi, record, 40, image, length) == EIO);
	CHECK(!dst.vsd_session_restore_staged);
	uint8_t retained_gate[16];
	memcpy(retained_gate, dst.vsd_fresh_gate_token, 16);
	CHECK(memcmp(retained_gate, (const uint8_t[16]){0}, 16) != 0);
	destination_gate_failure = 0;
	if (migration) {
		source_retired = false;
		CHECK(pci_vtdtr_session_migration_release_paused(&pi, record, 40) == EBUSY);
		CHECK(pci_vtdtr_session_migration_stage_paused(&pi, record, 40, image, length) == 0);
		CHECK(pci_vtdtr_session_migration_release_paused(&pi, record, 40) == EBUSY);
	} else
		CHECK(pci_vtdtr_session_restore_stage_paused(&pi, record, 40, image, length) == 0);
	CHECK(memcmp(retained_gate, dst.vsd_fresh_gate_token, 16) == 0);
	CHECK(pci_vtdtr_resume(&dst) == EBUSY);
	struct vm_snapshot_meta restore = {
	    .buffer = {.buf_start = image, .buf_size = length, .buf = image, .buf_rem = length},
	    .op = VM_SNAPSHOT_RESTORE};
	destination_gate_failure = EBUSY;
	CHECK(pci_vtdtr_snapshot(&dst, &restore) == EBUSY && restore.buffer.buf_rem == length);
	CHECK(dst.vsd_session_restore_staged && !dst.vsd_session_restore_pending);
	destination_gate_failure = 0;
	image[16] ^= 1; /* Mutation after preflight must not be installed. */
	CHECK(pci_vtdtr_snapshot(&dst, &restore) == EPROTO && restore.buffer.buf_rem == length);
	CHECK(dst.vsd_session_restore_staged && !dst.vsd_session_restore_pending);
	image[16] ^= 1;
	CHECK(pci_vtdtr_snapshot(&dst, &restore) == 0 && restore.buffer.buf_rem == 0);
	CHECK(!dst.vsd_session_restore_staged && dst.vsd_session_restore_pending &&
	    dst.vsd_session_stopped && dst.vsd_ready == 0 && queue.count == 0 &&
	    dst.vsd_restore_planned == NULL && !dst.vsd_handoff_ticket_valid);
	CHECK(pci_vtdtr_resume(&dst) == EBUSY);
	if (migration) {
		CHECK(pci_vtdtr_session_migration_release_paused(&pi, record, 40) == EBUSY);
		dst.vsd_vs.vs_mtx = &dst.vsd_mtx;
		dst.vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
		dst.vsd_queues[1].vq_vs = &dst.vsd_vs;
		dst.vsd_queues[1].vq_num = 1;
		dst.vsd_queues[1].vq_qsize = VTDTR_RINGSZ;
		vq_set_allocated(&dst.vsd_queues[0], true);
		vq_set_allocated(&dst.vsd_queues[1], true);
		checkpoint_tx_use_available = checkpoint_tx_check_lock = true;
		available = 0;
		CHECK(pci_vtdtr_session_discard_paused(&pi) == 0);
		CHECK(pci_vtdtr_resume(&dst) == EBUSY);
		uint8_t wrong[40]; memcpy(wrong, record, sizeof(wrong)); wrong[24] ^= 1;
		CHECK(pci_vtdtr_session_migration_release_paused(&pi, wrong, 40) == ESTALE);
		destination_gate_failure = EIO;
		CHECK(pci_vtdtr_session_migration_release_paused(&pi, record, 40) == EIO);
		CHECK(!dst.vsd_session_migration_released);
		destination_gate_failure = 0;
		CHECK(pci_vtdtr_session_migration_release_paused(&pi, record, 40) == 0);
		CHECK(pci_vtdtr_session_migration_release_paused(&pi, record, 40) == 0);
		CHECK(pci_vtdtr_resume(&dst) == 0);
		pthread_mutex_lock(&dst.vsd_mtx);
		checkpoint_tx_use_available = checkpoint_tx_check_lock = false;
	}
	pthread_mutex_unlock(&dst.vsd_mtx);
	CHECK(pthread_cond_destroy(&dst.vsd_cond) == 0);
	CHECK(pthread_mutex_destroy(&dst.vsd_mtx) == 0);
	source_retired = false;
}

static void
test_session_stop(void)
{
	CHECK(pci_vtdtr_session_stop_begin((struct vmctx *)2) == ENXIO);
	for (int invalid = 0; invalid < 3; invalid++) {
		memset(session_gate_owner, 0, 16);
		session_gate_failure = 0;
		struct pci_vtdtr_softc sc = {0};
		struct pci_vtdtr_ctrlq queue = {0}, pending = {0};
		STAILQ_INIT(&queue.head);
		STAILQ_INIT(&pending.head);
		sc.vsd_ctrlq = &queue;
		sc.vsd_vmctx = (struct vmctx *)2;
		CHECK(pthread_mutex_init(&sc.vsd_mtx, NULL) == 0);
		init_monotonic_cond(&sc.vsd_cond);
		sc.vsd_vs.vs_mtx = &sc.vsd_mtx;
		sc.vsd_queues[0].vq_vs = &sc.vsd_vs;
		sc.vsd_queues[1].vq_vs = &sc.vsd_vs;
		vtdtr_shutdown_sc = &sc;
		CHECK(pci_vtdtr_session_stop_status(sc.vsd_vmctx) == ENOENT);
		CHECK(pci_vtdtr_session_stop_begin(sc.vsd_vmctx) == ENOTSUP);
		CHECK(!sc.vsd_session_stop_requested && queue.count == 0);
		sc.vsd_vs.vs_negotiated_caps = VTDTR_WIRE_F_SESSION_REQUIRED |
		    VTDTR_WIRE_F_SESSION_STOP_V1;
		CHECK(pci_vtdtr_session_checkpoint_begin(sc.vsd_vmctx) == ENOTSUP);
		CHECK(!sc.vsd_session_stop_requested && queue.count == 0 &&
		    memcmp(sc.vsd_session_gate_token, (uint8_t[16]){0}, 16) == 0 &&
		    memcmp(session_gate_owner, (uint8_t[16]){0}, 16) == 0);
		session_gate_failure = EIO;
		CHECK(pci_vtdtr_session_stop_begin(sc.vsd_vmctx) == EIO);
		CHECK(!sc.vsd_session_stop_requested && queue.count == 0);
		CHECK(pci_vtdtr_checkpoint_state_valid(&sc) == EBUSY);
		session_gate_failure = 0;
		CHECK(pci_vtdtr_session_stop_begin(sc.vsd_vmctx) == 0);
		uint64_t token = sc.vsd_session_stop_token;
		CHECK(token != 0 && queue.count == 1 &&
		    STAILQ_FIRST(&queue.head)->ctrl->pvc_event ==
		    VTDTR_DEVICE_SESSION_STOP);
		CHECK(pci_vtdtr_session_stop_begin(sc.vsd_vmctx) == 0 &&
		    queue.count == 1 && sc.vsd_session_stop_token == token);
		CHECK(pci_vtdtr_session_checkpoint_begin(sc.vsd_vmctx) == ENOTSUP);
		sc.vsd_vs.vs_negotiated_caps |= VTDTR_WIRE_F_SESSION_FRESH_V1;
		CHECK(pci_vtdtr_session_checkpoint_begin(sc.vsd_vmctx) == 0 &&
		    queue.count == 1 && sc.vsd_session_stop_token == token);
		CHECK(pci_vtdtr_session_stop_status(sc.vsd_vmctx) == EBUSY);
		bool complete = true;
		CHECK(pci_vtdtr_session_collectors_stop_step(sc.vsd_vmctx, &complete) == EBUSY && !complete);
		struct pci_vtdtr_control old_elf = {.pvc_event = VTDTR_DEVICE_ELF};
		struct iovec old_iov = {&old_elf, sizeof(old_elf)};
		pthread_mutex_lock(&sc.vsd_mtx);
		sc.vsd_ready = 1;
		CHECK(pci_vtdtr_control_rx(&sc, &old_iov, 1) == 0 &&
		    sc.vsd_ready == 0);
		pthread_mutex_unlock(&sc.vsd_mtx);
		CHECK(pci_vtdtr_checkpoint_state_valid(&sc) == EBUSY);
		struct pci_vtdtr_ctrl_entry *late = calloc(1, sizeof(*late));
		CHECK(late != NULL);
		late->ctrl = calloc(1, sizeof(*late->ctrl));
		CHECK(late->ctrl != NULL);
		pci_vtdtr_cq_enqueue(&pending, late);
		CHECK(!pci_vtdtr_publish(&sc, &pending, sc.vsd_generation, false));
		CHECK(pending.count == 0 && queue.count == 1);
		struct pci_vtdtr_control stopped = {
		    .pvc_event = VTDTR_DEVICE_SESSION_STOPPED,
		    .pvc_cleanup_vmid = sc.vsd_session_stop_vmid,
		    .pvc_cleanup_epoch = sc.vsd_session_stop_epoch,
		    .pvc_cleanup_delivery_id = token };
		struct iovec iov = {&stopped, sizeof(stopped)};
		if (invalid == 1)
			stopped.pvc_cleanup_delivery_id ^= 1;
		sc.vsd_session_stop_delivered = invalid != 2;
		pthread_mutex_lock(&sc.vsd_mtx);
		CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == (invalid ? 1 : 0));
		pthread_mutex_unlock(&sc.vsd_mtx);
		CHECK(sc.vsd_session_stopped == (invalid == 0));
		CHECK(pci_vtdtr_session_stop_status(sc.vsd_vmctx) ==
		    (invalid ? ENXIO : 0));
		if (!invalid) {
			uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE];
			struct hypertrace_session_record record;
			CHECK(pci_vtdtr_session_checkpoint_export(sc.vsd_vmctx,
			    wire, sizeof(wire)) == EBUSY);
			sc.vsd_vs.vs_negotiated_caps |= VTDTR_WIRE_F_SESSION_FRESH_V1;
			collector_step_result = -1; collector_step_error = EIO;
			CHECK(pci_vtdtr_session_collectors_stop_step(sc.vsd_vmctx, &complete) == EIO && !complete);
			CHECK(!sc.vsd_session_collectors_busy && !sc.vsd_session_collectors_stopped);
			collector_step_result = 1;
			CHECK(pci_vtdtr_session_collectors_stop_step(sc.vsd_vmctx, &complete) == 0 && !complete);
			CHECK(pci_vtdtr_session_checkpoint_export(sc.vsd_vmctx, wire, sizeof(wire)) == EBUSY);
			collector_step_result = 0; collector_change_token = true;
			CHECK(pci_vtdtr_session_collectors_stop_step(sc.vsd_vmctx, &complete) == ESTALE && !complete);
			sc.vsd_session_stop_token = token; collector_change_token = false;
			collector_gate_loss = true;
			CHECK(pci_vtdtr_session_collectors_stop_step(sc.vsd_vmctx, &complete) == EBUSY && !complete);
			collector_gate_loss = false; session_gate_failure = 0;
			CHECK(pci_vtdtr_session_collectors_stop_step(sc.vsd_vmctx, &complete) == 0 && complete);
			int calls = collector_step_calls;
			CHECK(pci_vtdtr_session_collectors_stop_step(sc.vsd_vmctx, &complete) == 0 && complete && collector_step_calls == calls);
			CHECK(pci_vtdtr_session_checkpoint_export(sc.vsd_vmctx,
			    wire, sizeof(wire)) == 0);
			CHECK(hypertrace_session_record_decode(wire, sizeof(wire), &record) == 0 &&
			    record.stop_token == token && record.vmid == sc.vsd_session_stop_vmid);
			/* Model the STOP descriptor having left the private queue. */
			pthread_mutex_lock(&sc.vsd_mtx);
			pci_vtdtr_reset_queue(&sc);
			pthread_mutex_unlock(&sc.vsd_mtx);
			sc.vsd_session_collectors_stopped = false;
			CHECK(pci_vtdtr_pause(&sc) == EBUSY && !sc.vsd_checkpoint_paused);
			sc.vsd_session_collectors_stopped = true;
			CHECK(pci_vtdtr_pause(&sc) == 0);
			sc.vsd_queues[1].vq_num = 1;
			uint8_t image[512] = {0};
			struct vm_snapshot_meta save = {
			    .buffer = {.buf_start = image, .buf_size = sizeof(image),
			        .buf = image, .buf_rem = sizeof(image)},
			    .op = VM_SNAPSHOT_SAVE };
			checkpoint_tx_pending = true;
			CHECK(pci_vtdtr_snapshot(&sc, &save) == EBUSY && save.buffer.buf_rem == sizeof(image));
			checkpoint_tx_pending = false;
			sc.vsd_inbound_delivery_id = 1;
			CHECK(pci_vtdtr_snapshot(&sc, &save) == EPROTO);
			sc.vsd_inbound_delivery_id = 0;
			CHECK(pci_vtdtr_snapshot(&sc, &save) == 0);
			struct pci_vtdtr_checkpoint_stage stage = {0};
			CHECK(stage_private_image(image, sizeof(image) - save.buffer.buf_rem, &stage) == 0);
			CHECK(stage.count == 0 && stage.partial_total == 0 &&
			    stage.guest_ready == 0 && stage.ready == 0 &&
			    stage.source_vmid == record.vmid && stage.source_epoch == record.epoch);
			pci_vtdtr_checkpoint_stage_clear(&stage);
			CHECK(pci_vtdtr_resume(&sc) == 0);
			test_fresh_private_restore(image, sizeof(image) - save.buffer.buf_rem, wire, false);
			test_fresh_private_restore(image, sizeof(image) - save.buffer.buf_rem, wire, true);
			session_gate_failure = EBUSY;
			CHECK(pci_vtdtr_session_stop_status(sc.vsd_vmctx) == EBUSY);
			CHECK(pci_vtdtr_session_checkpoint_export(sc.vsd_vmctx,
			    wire, sizeof(wire)) == EBUSY);
			session_gate_failure = 0;
		}
		pthread_mutex_lock(&sc.vsd_mtx);
		if (!invalid) {
			CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 0);
			int resets = reset_calls;
			pci_vtdtr_reset(&sc);
			CHECK(reset_calls == resets && sc.vsd_session_stop_requested);
		}
		pci_vtdtr_reset_queue(&sc);
		pthread_mutex_unlock(&sc.vsd_mtx);
		vtdtr_shutdown_sc = NULL;
		CHECK(pthread_cond_destroy(&sc.vsd_cond) == 0);
		CHECK(pthread_mutex_destroy(&sc.vsd_mtx) == 0);
	}
}

static void
test_fresh_record(void)
{
	uint8_t wire[HYPERTRACE_SESSION_RECORD_SIZE];
	struct hypertrace_session_record record = {42, 99, 123, HYPERTRACE_SESSION_FEATURES};
	struct hypertrace_session_record decoded = {0};
	CHECK(hypertrace_session_record_encode(wire, sizeof(wire), &record) == 0);
	CHECK(memcmp(wire, "FSS1", 4) == 0);
	for (size_t n = 0; n < sizeof(wire); n++) {
		CHECK(hypertrace_session_record_decode(wire, n, &decoded) == EINVAL);
		CHECK(decoded.vmid == 0);
	}
	wire[10] = 1;
	CHECK(hypertrace_session_record_decode(wire, sizeof(wire), &decoded) == EPROTO);
	wire[10] = 0;
	CHECK(hypertrace_session_record_decode(wire, sizeof(wire), &decoded) == 0 &&
	    decoded.vmid == 42 && decoded.epoch == 99 && decoded.stop_token == 123);
	struct pci_vtdtr_softc sc = {0};
	struct pci_vtdtr_ctrlq queue = {0};
	STAILQ_INIT(&queue.head);
	sc.vsd_ctrlq = &queue;
	sc.vsd_vmctx = (struct vmctx *)1;
	sc.vsd_vs.vs_negotiated_caps = HYPERTRACE_SESSION_FEATURES;
	struct pci_devemu emu = { .pe_emu = "virtio-dtrace",
	    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
	struct pci_devinst pi = { .pi_d = &emu, .pi_arg = &sc };
	CHECK(pthread_mutex_init(&sc.vsd_mtx, NULL) == 0);
	pthread_mutex_lock(&sc.vsd_mtx);
	CHECK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == EBUSY);
	sc.vsd_checkpoint_paused = true;
	struct pci_vtdtr_ctrl_entry *old = calloc(1, sizeof(*old));
	CHECK(old != NULL);
	old->ctrl = calloc(1, sizeof(*old->ctrl));
	CHECK(old->ctrl != NULL);
	pci_vtdtr_cq_enqueue(&queue, old);
	sc.vsd_inbound_elf.data = malloc(4);
	CHECK(sc.vsd_inbound_elf.data != NULL);
	source_retired = false;
	CHECK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == EBUSY &&
	    queue.count == 1 && sc.vsd_inbound_elf.data != NULL);
	source_retired = true;
	bool *busy_states[] = { &sc.vsd_restored_kill_wait,
	    &sc.vsd_cleanup_unapplied, &sc.vsd_rekey_ack_pending,
	    &sc.vsd_rekey_ack_sent, &sc.vsd_rekey_receipt_reply_pending,
	    &sc.vsd_ticket_wait };
	for (size_t i = 0; i < sizeof(busy_states) / sizeof(busy_states[0]); i++) {
		*busy_states[i] = true;
		CHECK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire,
		    sizeof(wire)) == EBUSY && queue.count == 1 &&
		    sc.vsd_inbound_elf.data != NULL && !sc.vsd_session_stopped);
		*busy_states[i] = false;
	}
	CHECK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == 0);
	CHECK(queue.count == 0 && sc.vsd_inbound_elf.data == NULL &&
	    sc.vsd_session_stopped && sc.vsd_session_stop_requested &&
	    sc.vsd_session_stop_vmid == 42 && sc.vsd_session_stop_epoch == 99 &&
	    sc.vsd_session_stop_token == 123 && sc.vsd_checkpoint_paused);
	CHECK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == 0);
	record.stop_token++;
	CHECK(hypertrace_session_record_encode(wire, sizeof(wire), &record) == 0);
	CHECK(pci_vtdtr_session_checkpoint_import_paused(&pi, wire, sizeof(wire)) == ESTALE &&
	    sc.vsd_session_stop_token == 123);
	CHECK(sc.vsd_session_restore_pending && pci_vtdtr_resume(&sc) == EBUSY);
	sc.vsd_vs.vs_mtx = &sc.vsd_mtx;
	sc.vsd_queues[1].vq_vs = &sc.vsd_vs;
	sc.vsd_queues[1].vq_num = 1;
	sc.vsd_queues[1].vq_qsize = VTDTR_RINGSZ;
	CHECK(pci_vtdtr_session_discard_paused(&pi) == EBUSY);
	sc.vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	vq_set_allocated(&sc.vsd_queues[0], true);
	vq_set_allocated(&sc.vsd_queues[1], true);
	checkpoint_tx_use_available = checkpoint_tx_check_lock = true;
	const struct pci_vtdtr_control stale[] = {
	    { .pvc_event = VTDTR_DEVICE_ELF },
	    { .pvc_event = VTDTR_DEVICE_KILL },
	};
	incoming_controls = stale;
	incoming_index = 0;
	available = nitems(stale);
	int previous_writes = writes, previous_completions = discarded_completions;
	source_retired = false;
	CHECK(pci_vtdtr_session_discard_paused(&pi) == EBUSY &&
	    available == nitems(stale) && sc.vsd_session_restore_pending);
	source_retired = true;
	checkpoint_tx_error = EFAULT;
	CHECK(pci_vtdtr_session_discard_paused(&pi) == EFAULT &&
	    available == nitems(stale) && sc.vsd_session_restore_pending);
	checkpoint_tx_error = 0;
	CHECK(pci_vtdtr_session_discard_paused(&pi) == 0 && available == 0 &&
	    discarded_completions == previous_completions + nitems(stale) &&
	    writes == previous_writes && !sc.vsd_session_restore_pending &&
	    sc.vsd_session_stopped && sc.vsd_checkpoint_paused);
	CHECK(pci_vtdtr_session_discard_paused(&pi) == EBUSY);
	/* A paused guest cannot refill the ring. More than one ring's worth
	 * of pending heads, or a wrong-direction chain, must remain fenced. */
	sc.vsd_session_restore_pending = true;
	sc.vsd_queues[1].vq_qsize = 1;
	incoming_index = 0;
	available = nitems(stale);
	CHECK(pci_vtdtr_session_discard_paused(&pi) == EPROTO && available == 1 &&
	    sc.vsd_session_restore_pending && pci_vtdtr_resume(&sc) == EBUSY &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	sc.vsd_vs.vs_status = VIRTIO_CONFIG_STATUS_DRIVER_OK;
	sc.vsd_queues[1].vq_qsize = VTDTR_RINGSZ;
	incoming_controls = NULL;
	available = 1;
	CHECK(pci_vtdtr_session_discard_paused(&pi) == EPROTO &&
	    sc.vsd_session_restore_pending &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	available = 0;
	incoming_index = 0;
	checkpoint_tx_use_available = checkpoint_tx_check_lock = false;
	pthread_mutex_unlock(&sc.vsd_mtx);
	CHECK(pthread_mutex_destroy(&sc.vsd_mtx) == 0);
}

static void
test_fresh_attach(void)
{
	for (int invalid = 0; invalid < 4; invalid++) {
		memset(destination_gate_owner, 0, 16);
		destination_gate_failure = 0;
		destination_released = false;
		struct pci_vtdtr_softc sc = {0};
		struct pci_vtdtr_ctrlq queue = {0};
		STAILQ_INIT(&queue.head);
		sc.vsd_ctrlq = &queue;
		sc.vsd_vmctx = (struct vmctx *)1;
		CHECK(pthread_mutex_init(&sc.vsd_mtx, NULL) == 0);
		init_monotonic_cond(&sc.vsd_cond);
		sc.vsd_vs.vs_mtx = &sc.vsd_mtx;
		sc.vsd_queues[0].vq_vs = &sc.vsd_vs;
		sc.vsd_queues[1].vq_vs = &sc.vsd_vs;
		vtdtr_shutdown_sc = &sc;
		CHECK(pci_vtdtr_session_attach_status(sc.vsd_vmctx) == ENOENT);
		CHECK(pci_vtdtr_session_authorize(sc.vsd_vmctx) == EBUSY);
		CHECK(pci_vtdtr_session_attach_begin(sc.vsd_vmctx) == EBUSY);
		sc.vsd_session_stop_requested = sc.vsd_session_stopped = true;
		sc.vsd_session_stop_vmid = 42;
		sc.vsd_session_stop_epoch = 99;
		sc.vsd_session_stop_token = 123;
		CHECK(pci_vtdtr_session_attach_begin(sc.vsd_vmctx) == ENOTSUP);
		sc.vsd_vs.vs_negotiated_caps = VTDTR_WIRE_F_SESSION_FRESH_V1;
		source_retired = false;
		CHECK(pci_vtdtr_session_attach_begin(sc.vsd_vmctx) == EBUSY && queue.count == 0);
		source_retired = true;
		CHECK(pci_vtdtr_session_attach_begin(sc.vsd_vmctx) == 0 && queue.count == 1);
		CHECK(pci_vtdtr_session_attach_begin(sc.vsd_vmctx) == 0 && queue.count == 1);
		destination_gate_failure = EIO;
		CHECK(pci_vtdtr_session_attach_begin(sc.vsd_vmctx) == EIO && queue.count == 1);
		CHECK(pci_vtdtr_session_attach_status(sc.vsd_vmctx) == EIO);
		destination_gate_failure = 0;
		CHECK(pci_vtdtr_session_attach_status(sc.vsd_vmctx) == EBUSY);
		struct timespec deadline = sc.vsd_fresh_deadline;
		sc.vsd_fresh_deadline = (struct timespec){0};
		CHECK(pci_vtdtr_session_attach_status(sc.vsd_vmctx) == ETIMEDOUT &&
		    sc.vsd_session_stop_requested);
		sc.vsd_fresh_deadline = deadline;
		struct pci_vtdtr_control reply = *STAILQ_FIRST(&queue.head)->ctrl;
		CHECK(reply.pvc_event == VTDTR_DEVICE_SESSION_PREPARE &&
		    pci_vtdtr_ctrl_matches_vm(&reply, 43, 100) &&
		    !pci_vtdtr_ctrl_matches_vm(&reply, 42, 99));
		pthread_mutex_lock(&sc.vsd_mtx);
		pci_vtdtr_reset_queue(&sc);
		sc.vsd_fresh_prepare_delivered = invalid != 2;
		struct pci_vtdtr_control late_stop = {
		    .pvc_event = VTDTR_DEVICE_SESSION_STOPPED,
		    .pvc_cleanup_vmid = 42, .pvc_cleanup_epoch = 99,
		    .pvc_cleanup_delivery_id = 123 };
		struct iovec late_iov = {&late_stop, sizeof(late_stop)};
		CHECK(pci_vtdtr_control_rx(&sc, &late_iov, 1) == 0);
		reply.pvc_event = VTDTR_DEVICE_SESSION_READY;
		if (invalid == 1) reply.wire.uctrl.session_prepare.stop_token++;
		struct iovec iov = {&reply, sizeof(reply)};
		CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) ==
		    ((invalid == 1 || invalid == 2) ? 1 : 0));
		if (invalid == 0 || invalid == 3) {
			CHECK(queue.count == 1 && sc.vsd_fresh_commit_queued);
			CHECK(STAILQ_FIRST(&queue.head)->ctrl->pvc_event == VTDTR_DEVICE_SESSION_COMMIT);
			CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 0 && queue.count == 1);
			pci_vtdtr_reset_queue(&sc);
			sc.vsd_fresh_commit_delivered = invalid != 3;
			reply.pvc_event = VTDTR_DEVICE_SESSION_ACTIVE;
			CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == (invalid == 3 ? 1 : 0));
			if (!invalid) CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 0);
		}
		CHECK(sc.vsd_session_stop_requested);
		pthread_mutex_unlock(&sc.vsd_mtx);
		CHECK(pci_vtdtr_session_attach_status(sc.vsd_vmctx) == (invalid ? ENXIO : 0));
		if (!invalid) {
			uint64_t generation = sc.vsd_generation;
			release_failure = EIO;
			CHECK(pci_vtdtr_session_authorize(sc.vsd_vmctx) == EIO);
			CHECK(sc.vsd_session_stop_requested && !sc.vsd_fresh_released &&
			    sc.vsd_generation == generation && !sc.vsd_fresh_release_busy);
			release_failure = 0;
			int resets = reset_calls;
			/* ACTIVE must authorize even with no posted RX descriptor. */
			int saved_available = available;
			available = 0;
			pthread_t communicator;
			CHECK(pthread_create(&communicator, NULL, pci_vtdtr_run, &sc) == 0);
			pthread_mutex_lock(&sc.vsd_mtx);
			struct timespec until;
			CHECK(clock_gettime(CLOCK_MONOTONIC, &until) == 0);
			until.tv_sec += 2;
			while (!sc.vsd_fresh_released)
				CHECK(pthread_cond_timedwait(&sc.vsd_cond,
				    &sc.vsd_mtx, &until) == 0);
			sc.vsd_stopping = true;
			pthread_cond_broadcast(&sc.vsd_cond);
			pthread_mutex_unlock(&sc.vsd_mtx);
			CHECK(pthread_join(communicator, NULL) == 0);
			sc.vsd_stopping = false;
			available = saved_available;
			CHECK(!sc.vsd_session_stop_requested && !sc.vsd_session_stopped &&
			    sc.vsd_fresh_released && sc.vsd_generation != generation && reset_calls == resets + 1);
			int calls = release_calls;
			CHECK(pci_vtdtr_session_authorize(sc.vsd_vmctx) == 0 && release_calls == calls);
			CHECK(pci_vtdtr_session_attach_status(sc.vsd_vmctx) == 0);
			destination_gate_failure = EIO;
			CHECK(pci_vtdtr_session_authorize(sc.vsd_vmctx) == EIO);
			destination_gate_failure = 0;
			sc.vsd_vs.vs_negotiated_caps = HYPERTRACE_SESSION_FEATURES;
			CHECK(pci_vtdtr_session_stop_begin(sc.vsd_vmctx) == 0);
			CHECK(sc.vsd_session_stop_requested && !sc.vsd_session_stopped &&
			    !sc.vsd_session_collectors_stopped && !sc.vsd_session_stop_delivered &&
			    !sc.vsd_fresh_requested && !sc.vsd_fresh_released &&
			    sc.vsd_session_stop_vmid == 43 && sc.vsd_session_stop_epoch == 100);
			CHECK(pci_vtdtr_session_authorize(sc.vsd_vmctx) == EBUSY);
		}
		pthread_mutex_lock(&sc.vsd_mtx);
		pci_vtdtr_reset_queue(&sc);
		pthread_mutex_unlock(&sc.vsd_mtx);
		vtdtr_shutdown_sc = NULL;
		CHECK(pthread_cond_destroy(&sc.vsd_cond) == 0);
		CHECK(pthread_mutex_destroy(&sc.vsd_mtx) == 0);
	}
}

int main(void)
{
	struct pci_vtdtr_softc sc = { 0 };
	struct pci_devinst size_pi = { .pi_arg = &sc };
	struct pci_vtdtr_ctrlq queue = { 0 };
	struct pci_vtdtr_control ctrl = { .pvc_event = VTDTR_DEVICE_KILL };
	size_t extra;
	pthread_t worker;
	struct timespec until;

	alarm(5);
	test_session_stop();
	test_fresh_attach();
	test_fresh_record();
	CHECK((vtdtr_vi_consts.vc_hv_caps & VTDTR_WIRE_F_CONTROL_V1) != 0);
	CHECK((vtdtr_vi_consts.vc_hv_caps & VTDTR_WIRE_F_KILL_APPLIED_V1) != 0);
	CHECK((vtdtr_vi_consts.vc_hv_caps & VTDTR_WIRE_F_NODE_REKEY_V1) != 0);
	CHECK((vtdtr_vi_consts.vc_hv_caps & VTDTR_WIRE_F_HOST_ELF_DIGEST_V1) != 0);
	CHECK((vtdtr_vi_consts.vc_hv_caps & VTDTR_WIRE_F_REKEY_COMMIT_V1) != 0);
	CHECK((vtdtr_vi_consts.vc_hv_caps &
	    VTDTR_WIRE_F_REKEY_RECEIPT_V1) != 0);
	CHECK((vtdtr_vi_consts.vc_hv_caps &
	    VTDTR_WIRE_F_CLEANUP_APPLIED_V1) != 0);
	CHECK(pci_vtdtr_apply_features(&sc, 0) == EPROTO);
	CHECK(pci_vtdtr_apply_features(&sc,
	    VTDTR_WIRE_F_SESSION_REQUIRED) == 0);
	/* Basic tracing admission must not accidentally admit continuity restore. */
	CHECK(pci_vtdtr_checkpoint_features_validate(
	    VTDTR_WIRE_F_SESSION_REQUIRED) == EPROTO);
	const uint64_t session_bits[] = { VTDTR_WIRE_F_CONTROL_V1,
	    VTDTR_WIRE_F_KILL_APPLIED_V1, VTDTR_WIRE_F_HOST_ELF_DIGEST_V1,
	    VTDTR_WIRE_F_CLEANUP_APPLIED_V1 };
	for (size_t i = 0; i < sizeof(session_bits) / sizeof(session_bits[0]); i++)
		CHECK(pci_vtdtr_apply_features(&sc,
		    (VTDTR_WIRE_F_SESSION_REQUIRED | VTDTR_WIRE_F_CONTINUITY) &
		    ~session_bits[i]) == EPROTO);
	CHECK(pci_vtdtr_apply_features(&sc,
	    VTDTR_WIRE_F_CONTROL_V1) == EPROTO);
	CHECK(pci_vtdtr_apply_features(&sc,
	    VTDTR_WIRE_F_CONTROL_V1 | VTDTR_WIRE_F_KILL_APPLIED_V1) == EPROTO);
	CHECK(pci_vtdtr_apply_features(&sc,
	    VTDTR_WIRE_F_CONTROL_V1 | VTDTR_WIRE_F_KILL_APPLIED_V1 |
	    VTDTR_WIRE_F_NODE_REKEY_V1) == EPROTO);
	CHECK(pci_vtdtr_apply_features(&sc,
	    VTDTR_WIRE_F_CONTROL_V1 | VTDTR_WIRE_F_KILL_APPLIED_V1 |
	    VTDTR_WIRE_F_NODE_REKEY_V1 |
	    VTDTR_WIRE_F_HOST_ELF_DIGEST_V1) == EPROTO);
	CHECK(pci_vtdtr_apply_features(&sc,
	    VTDTR_WIRE_F_CONTROL_V1 | VTDTR_WIRE_F_KILL_APPLIED_V1 |
	    VTDTR_WIRE_F_NODE_REKEY_V1 |
	    VTDTR_WIRE_F_HOST_ELF_DIGEST_V1 |
	    VTDTR_WIRE_F_REKEY_COMMIT_V1) == EPROTO);
	CHECK(pci_vtdtr_apply_features(&sc,
	    VTDTR_WIRE_F_CONTROL_V1 | VTDTR_WIRE_F_KILL_APPLIED_V1 |
	    VTDTR_WIRE_F_NODE_REKEY_V1 |
	    VTDTR_WIRE_F_HOST_ELF_DIGEST_V1 |
	    VTDTR_WIRE_F_REKEY_COMMIT_V1 |
	    VTDTR_WIRE_F_CLEANUP_APPLIED_V1) == 0);
	test_init_failures();
	test_restore_kill_reserve();
	test_checkpoint_receipt_validation();
	test_private_image();
	test_checkpoint_stage_query();
	test_reader_pause();
	STAILQ_INIT(&queue.head); queue.count = 0;
	sc.vsd_ctrlq = &queue;
	CHECK(pthread_mutex_init(&sc.vsd_mtx, NULL) == 0);
	init_monotonic_cond(&sc.vsd_cond);
	sc.vsd_vs.vs_mtx = &sc.vsd_mtx;
	struct pci_devemu ticket_emu = {
	    .pe_emu = "virtio-dtrace",
	    .pe_snapshot_validate = pci_vtdtr_snapshot_validate };
	struct pci_devinst ticket_pi = {
	    .pi_d = &ticket_emu, .pi_arg = &sc };
	uint8_t ticket_token[16] = { 0xa1 };
	uint8_t ticket_digest[32] = { 0xb2 };
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    (const uint8_t[16]){0}, ticket_digest, NULL, 0) == EINVAL);
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, NULL, 0) == 0 &&
	    sc.vsd_handoff_ticket_valid);
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, NULL, 0) == 0);
	vm_epoch++;
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, NULL, 0) == EBUSY);
	vm_epoch--;
	admission_kills[0].pid = 456;
	admission_kills[0].vmid = 43;
	admission_kills[0].epoch = 100;
	admission_kills[0].source_id[0] = 0x56;
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, admission_kills, 1) == EBUSY);
	ticket_digest[0]++;
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, NULL, 0) == EBUSY);
	ticket_digest[0]--;
	pci_vtdtr_handoff_ticket_clear(&ticket_pi);
	CHECK(!sc.vsd_handoff_ticket_valid &&
	    sc.vsd_handoff_token[0] == 0 &&
	    sc.vsd_handoff_digest[0] == 0 &&
	    sc.vsd_handoff_vmid == 0 && sc.vsd_handoff_epoch == 0);
	/* The attested admission cut is inserted atomically between the saved
	 * rekey and ELF before the ticket opens the destination queue. */
	struct vmctx *original_ctx = sc.vsd_vmctx;
	sc.vsd_vmctx = (struct vmctx *)1;
	struct pci_vtdtr_ctrl_entry *saved_rekey = calloc(1,
	    sizeof(*saved_rekey));
	struct pci_vtdtr_ctrl_entry *manifest_saved_elf = calloc(1,
	    sizeof(*manifest_saved_elf));
	CHECK(saved_rekey != NULL && manifest_saved_elf != NULL);
	saved_rekey->ctrl = calloc(1, sizeof(*saved_rekey->ctrl));
	manifest_saved_elf->ctrl = calloc(1,
	    sizeof(*manifest_saved_elf->ctrl));
	CHECK(saved_rekey->ctrl != NULL &&
	    manifest_saved_elf->ctrl != NULL);
	saved_rekey->ctrl->pvc_event = VTDTR_DEVICE_NODE_REKEY;
	saved_rekey->restored_control = true;
	manifest_saved_elf->ctrl->pvc_event = VTDTR_DEVICE_ELF;
	manifest_saved_elf->restored_control = true;
	manifest_saved_elf->restored_elf_start = true;
	pci_vtdtr_cq_enqueue(&queue, saved_rekey);
	pci_vtdtr_cq_enqueue(&queue, manifest_saved_elf);
	sc.vsd_queues[0].vq_vs = &sc.vsd_vs;
	available = 1;
	int before_manifest_ready = completions;
	CHECK(pthread_mutex_lock(&sc.vsd_mtx) == 0);
	pci_vtdtr_notify_ready(&sc);
	CHECK(available == 1 && completions == before_manifest_ready &&
	    sc.vsd_ready == 0);
	CHECK(pthread_mutex_unlock(&sc.vsd_mtx) == 0);
	available = 0;
	admission_kills[0].pid = 456;
	admission_kills[0].vmid = 43;
	admission_kills[0].source_id[0] = 0x56;
	admission_kills[0].epoch = 101;
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, admission_kills, 1) == ESTALE &&
	    !sc.vsd_handoff_ticket_valid && queue.count == 2);
	admission_kills[0].epoch = 100;
	CHECK(pthread_mutex_lock(&sc.vsd_mtx) == 0);
	CHECK(pci_vtdtr_handoff_ticket_attach_paused(&ticket_pi,
	    ticket_token, ticket_digest, admission_kills, 1) == EBUSY);
	sc.vsd_checkpoint_paused = true;
	sc.vsd_reader_active = true;
	CHECK(pci_vtdtr_handoff_ticket_attach_paused(&ticket_pi,
	    ticket_token, ticket_digest, admission_kills, 1) == EBUSY &&
	    queue.count == 2);
	sc.vsd_reader_active = false;
	CHECK(pci_vtdtr_handoff_ticket_attach_paused(&ticket_pi,
	    ticket_token, ticket_digest, admission_kills, 1) == 0 &&
	    sc.vsd_handoff_ticket_valid && queue.count == 3 &&
	    queue.restored_kills == 1);
	sc.vsd_checkpoint_paused = false;
	CHECK(pthread_mutex_unlock(&sc.vsd_mtx) == 0);
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, admission_kills, 1) == 0 &&
	    sc.vsd_handoff_ticket_valid && queue.count == 3);
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, admission_kills, 1) == 0 &&
	    queue.count == 3);
	admission_kills[0].pid++;
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, admission_kills, 1) == EBUSY &&
	    queue.count == 3);
	admission_kills[0].pid--;
	struct pci_vtdtr_ctrl_entry *manifest_kill =
	    STAILQ_NEXT(saved_rekey, entries);
	CHECK(manifest_kill->ctrl->pvc_event == VTDTR_DEVICE_KILL &&
	    manifest_kill->ctrl->pvc_pid == 456 &&
	    manifest_kill->ctrl->pvc_kill_vmid == 43 &&
	    manifest_kill->ctrl->pvc_kill_epoch == 100 &&
	    manifest_kill->ctrl->pvc_source_id[0] == 0x56 &&
	    manifest_kill->restored_kill &&
	    STAILQ_NEXT(manifest_kill, entries) == manifest_saved_elf);
	pci_vtdtr_handoff_ticket_clear(&ticket_pi);
	CHECK(sc.vsd_replay_manifest_digest[0] == 0);
	for (unsigned i = 0; i < 3; i++) {
		struct pci_vtdtr_ctrl_entry *removed =
		    pci_vtdtr_cq_dequeue(&queue);
		CHECK(removed != NULL);
		free(removed->ctrl);
		free(removed);
	}
	CHECK(queue.count == 0 && queue.restored_kills == 0);
	sc.vsd_vmctx = original_ctx;
	sc.vsd_checkpoint_paused = true;
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, NULL, 0) == EBUSY);
	sc.vsd_checkpoint_paused = false;
	/* EOF closes a batch, but a READY-only batch may be followed by a
	 * second batch before the host receives this interrupt. */
	const struct pci_vtdtr_control batches[] = {
	    { .pvc_event = VTDTR_DEVICE_READY },
	    { .pvc_event = VTDTR_DEVICE_EOF },
	    { .pvc_event = VTDTR_DEVICE_NODE_ID, .pvc_node_query_id = 777 },
	};
	sc.vsd_queues[0].vq_vs = &sc.vsd_vs;
	sc.vsd_queues[1].vq_vs = &sc.vsd_vs;
	sc.vsd_queues[1].vq_qsize = nitems(batches);
	incoming_controls = batches;
	incoming_index = 0;
	available = nitems(batches);
	CHECK(pthread_mutex_lock(&sc.vsd_mtx) == 0);
	pci_vtdtr_notify_rx(&sc, &sc.vsd_queues[1]);
	CHECK(incoming_index == nitems(batches) && available == 0 &&
	    queue.count == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	struct pci_vtdtr_ctrl_entry *batch_reply = pci_vtdtr_cq_dequeue(&queue);
	CHECK(batch_reply->ctrl->pvc_event == VTDTR_DEVICE_NODE_ID &&
	    batch_reply->ctrl->pvc_node_query_id == 777);
	free(batch_reply->ctrl);
	free(batch_reply);
	CHECK(pthread_mutex_unlock(&sc.vsd_mtx) == 0);
	incoming_controls = NULL;
	sc.vsd_guest_ready = 0;
	CHECK(pci_de_vdtr.pe_snapshot_extra_capacity ==
	    pci_vtdtr_snapshot_extra_capacity);
	CHECK(pci_vtdtr_snapshot_extra_capacity(NULL, &extra) == EINVAL);
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_snapshot_extra_capacity(&size_pi, &extra) == 0 &&
	    extra == 0);
	CHECK(pthread_mutex_trylock(&sc.vsd_mtx) == EBUSY);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	struct pci_vtdtr_ctrl_entry queued = { .ctrl = &ctrl };
	ctrl.pvc_kill_vmid = 42;
	ctrl.pvc_kill_epoch = 98;
	ctrl.pvc_pid = 3;
	ctrl.pvc_source_id[0] = 1;
	pci_vtdtr_cq_enqueue(&queue, &queued);
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	CHECK(pthread_mutex_trylock(&sc.vsd_mtx) == 0);
	pthread_mutex_unlock(&sc.vsd_mtx);
	ctrl.pvc_kill_epoch = 99;
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_snapshot_extra_capacity(&size_pi, &extra) == 0 &&
	    extra >= sizeof(ctrl));
	CHECK(pci_vtdtr_resume(&sc) == 0);
	ctrl.pvc_pid = 1;
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	ctrl.pvc_pid = 3;
	ctrl.pvc_source_id[0] = 0;
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	ctrl.pvc_source_id[0] = 1;
	ctrl.pvc_event = VTDTR_DEVICE_ELF;
	ctrl.pvc_vmid = 42;
	ctrl.pvc_epoch = 99;
	ctrl.pvc_delivery_id = 7;
	ctrl.pvc_program_id[0] = 1;
	ctrl.pvc_elf_source_id[0] = 2;
	ctrl.pvc_totalelflen = 8;
	ctrl.pvc_elflen = PCI_VTDTR_MAXELFLEN + 1;
	ctrl.pvc_elfhasmore = 1;
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	ctrl.pvc_elflen = 4;
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	ctrl.pvc_totalelflen = 4;
	ctrl.pvc_elfhasmore = 0;
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	CHECK(pci_vtdtr_cq_dequeue(&queue) == &queued);
	CHECK(queue.count == 0);
	queue.count = 1;
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	queue.count = 0;
	sc.vsd_inbound_delivery_id = 7;
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	sc.vsd_inbound_delivery_id = 0;
	sc.vsd_inbound_elf.data = malloc(8);
	CHECK(sc.vsd_inbound_elf.data != NULL);
	sc.vsd_inbound_elf.total = 8;
	sc.vsd_inbound_elf.received = 4;
	sc.vsd_inbound_elf.identifier = 1;
	sc.vsd_inbound_delivery_id = 7;
	sc.vsd_inbound_vmid = 42;
	sc.vsd_inbound_epoch = 99;
	sc.vsd_inbound_program_id[0] = 1;
	sc.vsd_inbound_source_id[0] = 2;
	CHECK(pci_vtdtr_pause(&sc) == 0);
	CHECK(pci_vtdtr_snapshot_extra_capacity(&size_pi, &extra) == 0 &&
	    extra >= sc.vsd_inbound_elf.received + 4096);
	CHECK(pci_vtdtr_resume(&sc) == 0);
	sc.vsd_inbound_epoch = 98;
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	sc.vsd_inbound_epoch = 99;
	sc.vsd_inbound_elf.received = sc.vsd_inbound_elf.total;
	CHECK(pci_vtdtr_pause(&sc) == EPROTO);
	hypertrace_elf_reset(&sc.vsd_inbound_elf);
	sc.vsd_inbound_delivery_id = 0;
	sc.vsd_inbound_vmid = 0;
	sc.vsd_inbound_epoch = 0;
	sc.vsd_inbound_program_id[0] = 0;
	sc.vsd_inbound_source_id[0] = 0;
	/* TEST-ANCHOR: checkpoint-rejected */
	CHECK(pci_vtdtr_snapshot(&sc, NULL) == EOPNOTSUPP);
	CHECK(pci_vtdtr_snapshot_validate(NULL) == EOPNOTSUPP);
	CHECK(pthread_mutex_trylock(&sc.vsd_mtx) == 0);
	pthread_mutex_unlock(&sc.vsd_mtx);
	sc.vsd_queues[0].vq_vs = &sc.vsd_vs;
	sc.vsd_queues[0].vq_qsize = 8;
	pthread_mutex_lock(&sc.vsd_mtx);
	/* Actual callbacks run under the existing non-recursive device lock. */
	pci_vtdtr_notify_tx(&sc, &sc.vsd_queues[0]);
	CHECK(sc.vsd_ready == 0);
	available = 1;
	pci_vtdtr_notify_tx(&sc, &sc.vsd_queues[0]);
	CHECK(sc.vsd_ready == 1 && completions == 1);
	CHECK(output.pvc_event == VTDTR_DEVICE_READY);
	pci_vtdtr_node_id(&sc, 0);
	CHECK(queue.count == 1);
	CHECK(pci_vtdtr_fill_desc(&sc.vsd_queues[0], &ctrl) == false);
	CHECK(queue.count == 1);
	available = 1; malformed = 1;
	CHECK(pci_vtdtr_fill_desc(&sc.vsd_queues[0], &ctrl) == false);
	CHECK(sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET);
	CHECK(pci_vtdtr_suspend_device(&sc) == 0 && sc.vsd_suspended);
	pci_vtdtr_reset(&sc);
	CHECK(queue.count == 0 && sc.vsd_generation == transport_generation && sc.vsd_ready == 0);
	CHECK(sc.vsd_guest_ready == 0 && !sc.vsd_suspended);
	malformed = 0;
	/* Split messages at an unaligned boundary in both directions. */
	CHECK(pci_de_vdtr.pe_migration_flags == PCI_MIGRATION_VIRTIO_FLAGS);
	available = 1; split = 1;
	dma_dirty_bytes = dma_dirty_marks = 0;
	dma_expected = &ctrl;
	CHECK(pci_vtdtr_fill_desc(&sc.vsd_queues[0], &ctrl));
	CHECK(output.pvc_event == ctrl.pvc_event);
	CHECK(dma_dirty_marks == 2 && dma_dirty_bytes == sizeof(ctrl));
	split = 0; available = 1;
	dma_dirty_bytes = dma_dirty_marks = 0;
	CHECK(pci_vtdtr_fill_desc(&sc.vsd_queues[0], &ctrl));
	CHECK(dma_dirty_marks == 1 && dma_dirty_bytes == sizeof(ctrl));
	available = 1; malformed = 1;
	dma_dirty_bytes = dma_dirty_marks = 0;
	CHECK(!pci_vtdtr_fill_desc(&sc.vsd_queues[0], &ctrl));
	CHECK(dma_dirty_marks == 0 && dma_dirty_bytes == 0);
	malformed = 0; dma_expected = NULL;
	sc.vsd_vs.vs_status &= ~VIRTIO_CONFIG_S_NEEDS_RESET;
	struct pci_vtdtr_control ready = { .pvc_event = VTDTR_DEVICE_READY };
	struct iovec pieces[2] = { { &ready, 7 },
	    { (char *)&ready + 7, sizeof(ready) - 7 } };
	CHECK(pci_vtdtr_control_rx(&sc, pieces, 2) == 0);
	CHECK(sc.vsd_guest_ready == 1);
	/* A guest report releases the source fence only after the exact
	 * host-journal write succeeds, and returns an epoch-bound receipt. */
	struct pci_vtdtr_control cleanup_applied = {
	    .pvc_event = VTDTR_DEVICE_CLEANUP_APPLIED,
	    .pvc_cleanup_vmid = 42, .pvc_cleanup_epoch = 99,
	    .pvc_cleanup_delivery_id = 0x8899 };
	struct iovec cleanup_applied_iov = { &cleanup_applied,
	    sizeof(cleanup_applied) };
	int cleanup_before_writes = writes;
	sc.vsd_cleanup_unapplied = true;
	sc.vsd_cleanup_delivery_id = 0x8899;
	write_error = EIO;
	CHECK(pci_vtdtr_control_rx(&sc, &cleanup_applied_iov, 1) == 0 &&
	    sc.vsd_cleanup_unapplied && queue.count == 0);
	write_error = 0;
	queue.count = VTDTR_MAX_RESTORE_PENDING;
	CHECK(pci_vtdtr_control_rx(&sc, &cleanup_applied_iov, 1) == 0 &&
	    sc.vsd_cleanup_unapplied &&
	    queue.count == VTDTR_MAX_RESTORE_PENDING);
	queue.count = 0;
	CHECK(pci_vtdtr_control_rx(&sc, &cleanup_applied_iov, 1) == 0 &&
	    !sc.vsd_cleanup_unapplied && queue.count == 1 &&
	    last_write.msg_type == DTRACED_MSG_CLEANUP_APPLIED &&
	    last_write.cleanup.vmid == 42 &&
	    last_write.cleanup.epoch == 99 &&
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(last_write) == 0x8899);
	struct pci_vtdtr_ctrl_entry *cleanup_receipt =
	    pci_vtdtr_cq_dequeue(&queue);
	CHECK(cleanup_receipt != NULL &&
	    cleanup_receipt->ctrl->pvc_event ==
	    VTDTR_DEVICE_HOST_CLEANUP_APPLIED &&
	    cleanup_receipt->ctrl->pvc_cleanup_delivery_id == 0x8899);
	free(cleanup_receipt->ctrl);
	free(cleanup_receipt);
	writes = cleanup_before_writes;
	sc.vsd_cleanup_delivery_id = 0;
	/* Truncation must not partially overwrite the destination. */
	pieces[1].iov_len--;
	memset(&output, 0xa5, sizeof(output));
	CHECK(!pci_vtdtr_copy_control(pieces, 2, &output, false));
	for (size_t i = 0; i < sizeof(output); i++)
		CHECK(((unsigned char *)&output)[i] == 0xa5);
	struct hypertrace_vm_envelope target = {
	    .magic = HYPERTRACE_TARGET_MAGIC,
	    .version = HYPERTRACE_ENVELOPE_VERSION,
	    .vmid = 42, .epoch = 99 };
	struct { uint8_t target[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE];
	    char elf[4]; } packet = { 0 };
	hypertrace_envelope_encode(packet.target, &target);
	memcpy(packet.elf, "\177ELF", 4);
	size_t prefix;
	CHECK(pci_vtdtr_elf_target(&sc, &packet, sizeof(packet.target) + 4, &prefix) == 1);
	CHECK(prefix == sizeof(packet.target));
	target.epoch = 98;
	hypertrace_envelope_encode(packet.target, &target);
	CHECK(pci_vtdtr_elf_target(&sc, &packet, sizeof(packet.target) + 4, &prefix) == 0);
	target.epoch = 0;
	hypertrace_envelope_encode(packet.target, &target);
	CHECK(pci_vtdtr_elf_target(&sc, &packet, sizeof(packet.target) + 4, &prefix) == -1);
	CHECK(pci_vtdtr_elf_target(&sc, &packet, 3, &prefix) == -1);
	CHECK(pci_vtdtr_elf_target(&sc, "\177ELF", 4, &prefix) == 1 && prefix == 0);
	dtraced_hdr_t kill = { .msg_type = DTRACED_MSG_KILL };
	kill.kill.pid = 123; kill.kill.vmid = 42; kill.kill.epoch = 99;
	kill.kill.source_id[0] = 0x42;
	CHECK(pci_vtdtr_kill_matches(&sc, &kill));
	struct pci_vtdtr_control *kill_ctrl = vtdtr_kill_event(123, 42, 99,
	    kill.kill.source_id);
	CHECK(kill_ctrl != NULL && kill_ctrl->pvc_source_id[0] == 0x42 &&
	    kill_ctrl->pvc_kill_vmid == 42 &&
	    kill_ctrl->pvc_kill_epoch == 99);
	free(kill_ctrl);
	kill.kill.epoch = 98; CHECK(!pci_vtdtr_kill_matches(&sc, &kill));
	kill.kill.epoch = 99; kill.kill.vmid = 43;
	CHECK(!pci_vtdtr_kill_matches(&sc, &kill));
	kill.kill.vmid = 42; kill.kill.pid = -1;
	CHECK(!pci_vtdtr_kill_matches(&sc, &kill));
	dtraced_hdr_t cleanup = { .msg_type = DTRACED_MSG_CLEANUP };
	cleanup.cleanup.vmid = 42;
	cleanup.cleanup.epoch = 99;
	DTRACED_MSG_CLEANUP_DELIVERY_ID(cleanup) = 0x1234;
	CHECK(pci_vtdtr_cleanup_matches(&sc, &cleanup));
	cleanup.cleanup.epoch = 98;
	CHECK(!pci_vtdtr_cleanup_matches(&sc, &cleanup));
	cleanup.cleanup.epoch = 99;
	cleanup.cleanup.vmid = 43;
	CHECK(!pci_vtdtr_cleanup_matches(&sc, &cleanup));
	cleanup.cleanup.vmid = 0;
	CHECK(!pci_vtdtr_cleanup_matches(&sc, &cleanup));
	cleanup.cleanup.vmid = 42;
	vm_epoch = 100;
	CHECK(!pci_vtdtr_cleanup_matches(&sc, &cleanup));
	vm_epoch = 99;
	struct pci_vtdtr_control installed = { .pvc_event = VTDTR_DEVICE_INSTALLED };
	installed.pvc_installed_delivery_id = 17;
	installed.pvc_installed_vmid = 42;
	installed.pvc_installed_epoch = 99;
	installed.pvc_installed_program_id[0] = 0x42;
	installed.pvc_installed_source_id[0] = 0x55;
	struct iovec installed_iov = { &installed, sizeof(installed) };
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 0);
	CHECK(last_write.msg_type == DTRACED_MSG_INSTALLED &&
	    last_write.installed.delivery_id == 17 &&
	    last_write.installed.vmid == 42 &&
	    last_write.installed.epoch == 99 &&
	    last_write.installed.program_id[0] == 0x42 &&
	    last_write.installed.source_id[0] == 0x55 &&
	    strcmp(last_write.installed.name, "test") == 0);
	CHECK(queue.count == 1);
	struct pci_vtdtr_ctrl_entry *receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event == VTDTR_DEVICE_HOST_INSTALLED &&
	    receipt->ctrl->pvc_installed_delivery_id == 17 &&
	    receipt->ctrl->pvc_installed_vmid == 42 &&
	    receipt->ctrl->pvc_installed_epoch == 99 &&
	    receipt->ctrl->pvc_installed_program_id[0] == 0x42 &&
	    receipt->ctrl->pvc_installed_source_id[0] == 0x55);
	free(receipt->ctrl); free(receipt);
	struct pci_vtdtr_control identity_query = {
	    .pvc_event = VTDTR_DEVICE_NODE_ID };
	identity_query.pvc_node_query_id = 456;
	struct iovec identity_iov = { &identity_query, sizeof(identity_query) };
	sc.vsd_ready = 1;
	/* The query batch closed the guest's host-ready gate: the device must
	 * owe it a READY (vsd_ready 0), or the guest's next control stalls. */
	CHECK(pci_vtdtr_control_rx(&sc, &identity_iov, 1) == 0 &&
	    sc.vsd_ready == 0 && queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event == VTDTR_DEVICE_NODE_ID &&
	    receipt->ctrl->pvc_node_id == 42 &&
	    receipt->ctrl->pvc_node_epoch == 99 &&
	    receipt->ctrl->pvc_node_query_id == 456);
	free(receipt->ctrl); free(receipt);
	installed.pvc_event = VTDTR_DEVICE_UNINSTALLED;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 0);
	CHECK(last_write.msg_type == DTRACED_MSG_UNINSTALLED &&
	    last_write.installed.delivery_id == 17 &&
	    last_write.installed.epoch == 99);
	CHECK(queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event == VTDTR_DEVICE_HOST_UNINSTALLED);
	free(receipt->ctrl); free(receipt);
	installed.pvc_event = VTDTR_DEVICE_STATUS;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	pci_vtdtr_reset(&sc);
	installed.pvc_installed_query_id = 123;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 0 &&
	    last_write.msg_type == DTRACED_MSG_STATUS && queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event == VTDTR_DEVICE_HOST_STATUS &&
	    receipt->ctrl->pvc_installed_delivery_id == 17 &&
	    receipt->ctrl->pvc_installed_query_id == 123 &&
	    receipt->ctrl->pvc_installed_phase == 'i' &&
	    receipt->ctrl->pvc_installed_revoked == 1 &&
	    receipt->ctrl->pvc_installed_replay == 0);
	free(receipt->ctrl); free(receipt);
	status_grant = 1;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 0 &&
	    queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event == VTDTR_DEVICE_HOST_STATUS &&
	    receipt->ctrl->pvc_installed_replay == 1 &&
	    receipt->ctrl->pvc_installed_revoked == 0 &&
	    receipt->ctrl->pvc_installed_digest[0] == 0x42);
	free(receipt->ctrl); free(receipt);
	status_grant = 0;
	status_error = ENOTCONN;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 0 &&
	    queue.count == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event == VTDTR_DEVICE_HOST_STATUS &&
	    receipt->ctrl->pvc_installed_delivery_id == 17 &&
	    receipt->ctrl->pvc_installed_query_id == 123 &&
	    receipt->ctrl->pvc_installed_phase == 'u' &&
	    receipt->ctrl->pvc_installed_revoked == 0);
	free(receipt->ctrl); free(receipt);
	status_error = EPROTO;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 1 &&
	    queue.count == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	pci_vtdtr_reset(&sc);
	status_error = 0;
	installed.pvc_event = VTDTR_DEVICE_INGRESS_STATUS;
	installed.pvc_installed_vmid = 0;
	installed.pvc_installed_epoch = 0;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 0 &&
	    last_write.msg_type == DTRACED_MSG_INGRESS_STATUS &&
	    last_write.installed.vmid == 42 &&
	    last_write.installed.epoch == 99 &&
	    queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event ==
	    VTDTR_DEVICE_HOST_INGRESS_STATUS &&
	    receipt->ctrl->pvc_installed_phase == 'a' &&
	    receipt->ctrl->pvc_installed_digest[0] == 0x42 &&
	    receipt->ctrl->pvc_installed_vmid == 42 &&
	    receipt->ctrl->pvc_installed_epoch == 99 &&
	    receipt->ctrl->pvc_installed_query_id == 123);
	free(receipt->ctrl); free(receipt);
	status_error = ENOTCONN;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 0 &&
	    queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event ==
	    VTDTR_DEVICE_HOST_INGRESS_STATUS &&
	    receipt->ctrl->pvc_installed_phase == 'u' &&
	    receipt->ctrl->pvc_installed_digest[0] == 0);
	free(receipt->ctrl); free(receipt);
	status_error = EPROTO;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 1 &&
	    queue.count == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	pci_vtdtr_reset(&sc);
	status_error = 0;
	/* The guest cannot send a host-to-guest KILL or an unknown event. */
	struct pci_vtdtr_control invalid = {
	    .pvc_event = VTDTR_DEVICE_KILL,
	    .pvc_pid = 12345,
	};
	struct iovec invalid_iov = { &invalid, sizeof(invalid) };
	int invalid_writes = writes;
	CHECK(pci_vtdtr_control_rx(&sc, &invalid_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 &&
	    writes == invalid_writes && queue.count == 0);
	pci_vtdtr_reset(&sc);
	invalid.pvc_event = UINT32_MAX;
	CHECK(pci_vtdtr_control_rx(&sc, &invalid_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 &&
	    writes == invalid_writes && queue.count == 0);
	pci_vtdtr_reset(&sc);
	installed.pvc_installed_vmid = 42;
	installed.pvc_installed_epoch = 99;
	installed.pvc_event = VTDTR_DEVICE_STATUS;
	installed.pvc_installed_query_id = 0;
	installed.pvc_installed_phase = 'i';
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	pci_vtdtr_reset(&sc);
	installed.pvc_installed_phase = 0;
	installed.pvc_event = VTDTR_DEVICE_INSTALLED;
	write_error = EPIPE;
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) == 1 &&
	    queue.count == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	pci_vtdtr_reset(&sc);
	write_error = 0;
	writes = 0;
	struct pci_vtdtr_control applied = {
	    .pvc_event = VTDTR_DEVICE_KILL_APPLIED,
	    .pvc_pid = 12345,
	    .pvc_kill_vmid = 42,
	    .pvc_kill_epoch = 99 };
	applied.pvc_source_id[0] = 0x42;
	struct iovec applied_iov = { &applied, sizeof(applied) };
	write_error = EPIPE;
	CHECK(pci_vtdtr_control_rx(&sc, &applied_iov, 1) == 0 &&
	    queue.count == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	write_error = 0;
	CHECK(pci_vtdtr_control_rx(&sc, &applied_iov, 1) == 0 &&
	    last_write.msg_type == DTRACED_MSG_KILL_APPLIED &&
	    last_write.kill.pid == 12345 &&
	    last_write.kill.vmid == 42 && last_write.kill.epoch == 99 &&
	    last_write.kill.source_id[0] == 0x42 && queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event == VTDTR_DEVICE_HOST_KILL_APPLIED &&
	    receipt->ctrl->pvc_pid == 12345 &&
	    receipt->ctrl->pvc_kill_vmid == 42 &&
	    receipt->ctrl->pvc_kill_epoch == 99 &&
	    receipt->ctrl->pvc_source_id[0] == 0x42);
	free(receipt->ctrl); free(receipt);
	/* The restored outbound queue stays fenced across a lost host-daemon
	 * reply, and opens only after the exact guest-applied KILL is durable. */
	sc.vsd_restored_kill_wait = true;
	sc.vsd_restored_kill_pid = applied.pvc_pid;
	memcpy(sc.vsd_restored_kill_source_id, applied.pvc_source_id, 16);
	CHECK(clock_gettime(CLOCK_MONOTONIC,
	    &sc.vsd_restored_kill_deadline) == 0);
	sc.vsd_restored_kill_deadline.tv_sec += 60;
	sc.vsd_guest_ready = 0;
	write_error = EPIPE;
	CHECK(pci_vtdtr_control_rx(&sc, &applied_iov, 1) == 0 &&
	    sc.vsd_restored_kill_wait && !sc.vsd_guest_ready &&
	    queue.count == 0);
	write_error = 0;
	CHECK(pci_vtdtr_control_rx(&sc, &applied_iov, 1) == 0 &&
	    !sc.vsd_restored_kill_wait && sc.vsd_guest_ready &&
	    queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	free(receipt->ctrl); free(receipt);
	queue.count = VTDTR_MAX_RESTORE_PENDING;
	CHECK(pci_vtdtr_control_rx(&sc, &applied_iov, 1) == 0 &&
	    queue.count == VTDTR_MAX_RESTORE_PENDING &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0);
	queue.count = 0;
	write_error = EPROTO;
	CHECK(pci_vtdtr_control_rx(&sc, &applied_iov, 1) == 1 &&
	    queue.count == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	pci_vtdtr_reset(&sc);
	write_error = 0;
	writes = 0;
	/* A daemon transport failure must not acknowledge tracing as healthy. */
	struct pci_vtdtr_control elf = { .pvc_event = VTDTR_DEVICE_ELF,
	    .pvc_elflen = 4, .pvc_totalelflen = 4,
	    .pvc_delivery_id = 77, .pvc_vmid = 42, .pvc_epoch = 99 };
	elf.pvc_program_id[0] = 0x42;
	elf.pvc_elf_source_id[0] = 0x55;
	memcpy(elf.pvc_elf, "\177ELF", 4);
	struct iovec iov = { &elf, sizeof(elf) };
	elf.pvc_epoch = 98;
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1 && writes == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	pci_vtdtr_reset(&sc);
	elf.pvc_epoch = 99;
	write_error = EPIPE;
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1);
	CHECK(sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET);
	CHECK(sc.vsd_inbound_elf.data == NULL && writes == 1 &&
	    last_write.elf.delivery_id == 77);
	available = 1;
	int before_ready = completions;
	pci_vtdtr_notify_ready(&sc);
	CHECK(available == 1 && completions == before_ready && sc.vsd_ready == 0);
	pci_vtdtr_reset(&sc);
	/* Invalid guest content is rejected before any host daemon write. */
	memcpy(elf.pvc_elf, "bad!", 4);
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1 && writes == 1);
	CHECK(sc.vsd_inbound_elf.data == NULL);
	CHECK(sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET);
	pci_vtdtr_reset(&sc);
	memcpy(elf.pvc_elf, "\177ELF", 4);
	elf.pvc_delivery_id = 0;
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1 && writes == 1);
	CHECK(sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET);
	pci_vtdtr_reset(&sc);
	elf.pvc_delivery_id = 77;
	elf.pvc_identifier = 123;
	elf.pvc_elflen = 2;
	elf.pvc_elfhasmore = 1;
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 0 && writes == 1);
	elf.pvc_delivery_id = 78;
	elf.pvc_elfhasmore = 0;
	memcpy(elf.pvc_elf, "LF", 2);
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1 && writes == 1);
	CHECK(sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET);
	pci_vtdtr_reset(&sc);
	elf.pvc_delivery_id = 77;
	elf.pvc_identifier = 124;
	elf.pvc_elflen = 2;
	elf.pvc_elfhasmore = 1;
	memcpy(elf.pvc_elf, "\177E", 2);
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 0 &&
	    sc.vsd_inbound_elf.data != NULL && writes == 1);
	vm_epoch = 100;
	elf.pvc_elfhasmore = 0;
	memcpy(elf.pvc_elf, "LF", 2);
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1 &&
	    sc.vsd_inbound_elf.data == NULL && writes == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	vm_epoch = 99;
	pci_vtdtr_reset(&sc);
	write_error = 0;
	elf.pvc_delivery_id = 77;
	elf.pvc_elflen = elf.pvc_totalelflen = 4;
	elf.pvc_elfhasmore = 0;
	memcpy(elf.pvc_elf, "\177ELF", 4);
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 0 &&
	    last_upload.elf.delivery_id == 77 &&
	    last_write.msg_type == DTRACED_MSG_INGRESS_STATUS &&
	    last_write.installed.delivery_id == 77 && queue.count == 1);
	receipt = pci_vtdtr_cq_dequeue(&queue);
	CHECK(receipt->ctrl->pvc_event == VTDTR_DEVICE_HOST_ELF &&
	    receipt->ctrl->pvc_installed_delivery_id == 77 &&
	    receipt->ctrl->pvc_installed_vmid == 42 &&
	    receipt->ctrl->pvc_installed_epoch == 99 &&
	    receipt->ctrl->pvc_installed_program_id[0] == 0x42 &&
	    receipt->ctrl->pvc_installed_source_id[0] == 0x55);
	uint8_t elf_digest[32];
	CHECK(SHA256((const unsigned char *)"\177ELF", 4, elf_digest) != NULL &&
	    memcmp(receipt->ctrl->pvc_installed_digest, elf_digest, 32) == 0);
	free(receipt->ctrl); free(receipt);
	status_error = EPIPE;
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1 && queue.count == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	status_error = 0;
	pci_vtdtr_reset(&sc);
	ingress_bad_digest = 1;
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1 && queue.count == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ingress_bad_digest = 0;
	pci_vtdtr_reset(&sc);
	ingress_revoked = 1;
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1 && queue.count == 0 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	ingress_revoked = 0;
	pci_vtdtr_reset(&sc);
	pci_vtdtr_node_id(&sc, 0);
	sc.vsd_guest_ready = 1;
	sc.vsd_ready = 1;
	available = 0;
	pthread_mutex_unlock(&sc.vsd_mtx);
	/* A frame assembled before reset must neither enqueue nor fail the new session. */
	struct pci_vtdtr_ctrlq pending = { 0 };
	STAILQ_INIT(&pending.head); pending.count = 0;
	uint64_t current_generation = sc.vsd_generation;
	CHECK(!pci_vtdtr_publish(&sc, &pending, current_generation - 1, true));
	CHECK(!(sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET));
	for (int stale = 0; stale < 2; stale++) {
		struct pci_vtdtr_ctrl_entry *entry = calloc(1, sizeof(*entry));
		CHECK(entry != NULL);
		entry->ctrl = calloc(1, sizeof(*entry->ctrl));
		CHECK(entry->ctrl != NULL);
		entry->ctrl->pvc_event = VTDTR_DEVICE_CLEANUP_DTRACED;
		entry->ctrl->pvc_cleanup_vmid = 42;
		entry->ctrl->pvc_cleanup_epoch = 99;
		entry->ctrl->pvc_cleanup_delivery_id = 0x8899;
		pci_vtdtr_cq_enqueue(&pending, entry);
		size_t before = queue.count;
		CHECK(pci_vtdtr_publish(&sc, &pending,
		    current_generation - stale, false) == (stale == 0));
		CHECK(pending.count == 0);
		CHECK(queue.count == before + (stale ? 0 : 1));
	}
	CHECK(!pci_vtdtr_publish(&sc, &pending, current_generation, true));
	CHECK(sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET);
	struct pci_vtdtr_ctrl_entry *after_fault = calloc(1, sizeof(*after_fault));
	CHECK(after_fault != NULL);
	after_fault->ctrl = calloc(1, sizeof(*after_fault->ctrl));
	CHECK(after_fault->ctrl != NULL);
	pci_vtdtr_cq_enqueue(&pending, after_fault);
	size_t before_faulted_publish = queue.count;
	CHECK(!pci_vtdtr_publish(&sc, &pending, current_generation, false));
	CHECK(pending.count == 0 && queue.count == before_faulted_publish);
	int before_faulted_write = writes;
	CHECK(pci_vtdtr_control_rx(&sc, &iov, 1) == 1);
	CHECK(writes == before_faulted_write);
	pthread_mutex_lock(&sc.vsd_mtx);
	pci_vtdtr_reset(&sc);
	pci_vtdtr_node_id(&sc, 1234);
	sc.vsd_guest_ready = sc.vsd_ready = 1;
	pthread_mutex_unlock(&sc.vsd_mtx);
	CHECK(pthread_create(&worker, NULL, pci_vtdtr_run, &sc) == 0);
	pthread_mutex_lock(&sc.vsd_mtx);
	CHECK(queue.count == 1); /* No descriptor: keep the message queued. */
	CHECK(pci_vtdtr_suspend_device(&sc) == 0 && sc.vsd_suspended);
	available = 1;
	pci_vtdtr_notify_tx(&sc, &sc.vsd_queues[0]);
	clock_gettime(CLOCK_MONOTONIC, &until);
	until.tv_nsec += 20000000;
	if (until.tv_nsec >= 1000000000) {
		until.tv_sec++;
		until.tv_nsec -= 1000000000;
	}
	(void)pthread_cond_timedwait(&sc.vsd_cond, &sc.vsd_mtx, &until);
	CHECK(queue.count == 1);
	CHECK(pci_vtdtr_resume_device(&sc) == 0 && !sc.vsd_suspended);
	pci_vtdtr_resume_complete(&sc);
	clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
	while (queue.count != 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond, &sc.vsd_mtx, &until) == 0);
	CHECK(output.pvc_event == VTDTR_DEVICE_NODE_ID &&
	    output.pvc_node_id == 42 && output.pvc_node_epoch == 99 &&
	    output.pvc_node_query_id == 1234);
	struct pci_vtdtr_ctrl_entry *saved_kill =
	    calloc(1, sizeof(*saved_kill));
	struct pci_vtdtr_ctrl_entry *saved_elf =
	    calloc(1, sizeof(*saved_elf));
	CHECK(saved_kill != NULL && saved_elf != NULL);
	saved_kill->ctrl = calloc(1, sizeof(*saved_kill->ctrl));
	saved_elf->ctrl = calloc(1, sizeof(*saved_elf->ctrl));
	CHECK(saved_kill->ctrl != NULL && saved_elf->ctrl != NULL);
	saved_kill->restored_kill = true;
	saved_kill->ctrl->pvc_event = VTDTR_DEVICE_KILL;
	saved_kill->ctrl->pvc_pid = 123;
	saved_kill->ctrl->pvc_kill_vmid = 42;
	saved_kill->ctrl->pvc_kill_epoch = 99;
	saved_kill->ctrl->pvc_source_id[0] = 0x42;
	saved_elf->ctrl->pvc_event = VTDTR_DEVICE_ELF;
	saved_elf->ctrl->pvc_vmid = 42;
	saved_elf->ctrl->pvc_epoch = 99;
	pci_vtdtr_cq_enqueue(sc.vsd_ctrlq, saved_kill);
	pci_vtdtr_cq_enqueue(sc.vsd_ctrlq, saved_elf);
	sc.vsd_guest_ready = 1;
	available = 2;
	pci_vtdtr_notify_ready(&sc);
	CHECK(available == 2);
	int before_saved_kill = completions;
	pthread_cond_broadcast(&sc.vsd_cond);
	clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
	while (!sc.vsd_restored_kill_wait)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(queue.count == 1 && available == 1 &&
	    output.pvc_event == VTDTR_DEVICE_KILL &&
	    completions == before_saved_kill + 1 && !sc.vsd_guest_ready);
	pci_vtdtr_notify_ready(&sc);
	CHECK(available == 1 &&
	    output.pvc_event == VTDTR_DEVICE_KILL);
	struct pci_vtdtr_control saved_applied = {
	    .pvc_event = VTDTR_DEVICE_KILL_APPLIED,
	    .pvc_pid = 123, .pvc_kill_vmid = 42, .pvc_kill_epoch = 99,
	};
	saved_applied.pvc_source_id[0] = 0x42;
	struct iovec saved_applied_iov = {
	    &saved_applied, sizeof(saved_applied) };
	write_error = EPIPE;
	CHECK(pci_vtdtr_control_rx(&sc, &saved_applied_iov, 1) == 0 &&
	    sc.vsd_restored_kill_wait && queue.count == 1);
	write_error = 0;
	available = 2;
	CHECK(pci_vtdtr_control_rx(&sc, &saved_applied_iov, 1) == 0 &&
	    !sc.vsd_restored_kill_wait && sc.vsd_guest_ready &&
	    available == 1);
	clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
	while (available != 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(output.pvc_event == VTDTR_DEVICE_ELF && queue.count == 1);
	struct pci_vtdtr_ctrl_entry *saved_receipt =
	    pci_vtdtr_cq_dequeue(&queue);
	CHECK(saved_receipt->ctrl->pvc_event ==
	    VTDTR_DEVICE_HOST_KILL_APPLIED);
	free(saved_receipt->ctrl); free(saved_receipt);
	sc.vsd_restored_kill_wait = true;
	sc.vsd_restored_kill_pid = saved_applied.pvc_pid + 1;
	memcpy(sc.vsd_restored_kill_source_id,
	    saved_applied.pvc_source_id, 16);
	CHECK(clock_gettime(CLOCK_MONOTONIC,
	    &sc.vsd_restored_kill_deadline) == 0);
	sc.vsd_restored_kill_deadline.tv_sec += 60;
	CHECK(pci_vtdtr_control_rx(&sc, &saved_applied_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 &&
	    !sc.vsd_restored_kill_wait && queue.count == 0);
	pci_vtdtr_reset(&sc);
	struct pci_vtdtr_ctrl_entry *stale = calloc(1, sizeof(*stale));
	CHECK(stale != NULL);
	stale->ctrl = calloc(1, sizeof(*stale->ctrl));
	CHECK(stale->ctrl != NULL);
	stale->ctrl->pvc_event = VTDTR_DEVICE_ELF;
	stale->ctrl->pvc_vmid = 42;
	stale->ctrl->pvc_epoch = 99;
	pci_vtdtr_cq_enqueue(sc.vsd_ctrlq, stale);
	vm_epoch = 100;
	sc.vsd_guest_ready = 1;
	available = 1;
	int before_stale = completions;
	pthread_cond_broadcast(&sc.vsd_cond);
	clock_gettime(CLOCK_MONOTONIC, &until);
	until.tv_sec += 2;
	while ((sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(queue.count == 0 && completions == before_stale);
	vm_epoch = 99;
	pci_vtdtr_reset(&sc);
	stale = calloc(1, sizeof(*stale));
	CHECK(stale != NULL);
	stale->ctrl = calloc(1, sizeof(*stale->ctrl));
	CHECK(stale->ctrl != NULL);
	stale->ctrl->pvc_event = VTDTR_DEVICE_KILL;
	stale->ctrl->pvc_pid = 123;
	stale->ctrl->pvc_kill_vmid = 42;
	stale->ctrl->pvc_kill_epoch = 98;
	stale->ctrl->pvc_source_id[0] = 0x42;
	pci_vtdtr_cq_enqueue(sc.vsd_ctrlq, stale);
	sc.vsd_guest_ready = 1;
	available = 1;
	before_stale = completions;
	pthread_cond_broadcast(&sc.vsd_cond);
	clock_gettime(CLOCK_MONOTONIC, &until);
	until.tv_sec += 2;
	while ((sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(queue.count == 0 && completions == before_stale);
	pci_vtdtr_reset(&sc);
	stale = calloc(1, sizeof(*stale));
	CHECK(stale != NULL);
	stale->ctrl = calloc(1, sizeof(*stale->ctrl));
	CHECK(stale->ctrl != NULL);
	stale->ctrl->pvc_event = VTDTR_DEVICE_CLEANUP_DTRACED;
	stale->ctrl->pvc_cleanup_vmid = 42;
	stale->ctrl->pvc_cleanup_epoch = 98;
	stale->ctrl->pvc_cleanup_delivery_id = 0x8899;
	pci_vtdtr_cq_enqueue(sc.vsd_ctrlq, stale);
	sc.vsd_guest_ready = 1;
	available = 1;
	before_stale = completions;
	pthread_cond_broadcast(&sc.vsd_cond);
	clock_gettime(CLOCK_MONOTONIC, &until);
	until.tv_sec += 2;
	while ((sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(queue.count == 0 && completions == before_stale);
	pci_vtdtr_reset(&sc);
	sc.vsd_vmctx = (struct vmctx *)2;
	struct pci_vtdtr_ctrl_entry *rekey = calloc(1, sizeof(*rekey));
	CHECK(rekey != NULL);
	rekey->ctrl = calloc(1, sizeof(*rekey->ctrl));
	CHECK(rekey->ctrl != NULL);
	rekey->ctrl->pvc_event = VTDTR_DEVICE_NODE_REKEY;
	rekey->ctrl->pvc_rekey_old_id = 41;
	rekey->ctrl->pvc_rekey_old_epoch = 98;
	rekey->ctrl->pvc_rekey_new_id = 42;
	rekey->ctrl->pvc_rekey_new_epoch = 99;
	pci_vtdtr_cq_enqueue(sc.vsd_ctrlq, rekey);
	struct pci_vtdtr_ctrl_entry *after_rekey = calloc(1,
	    sizeof(*after_rekey));
	CHECK(after_rekey != NULL);
	after_rekey->ctrl = calloc(1, sizeof(*after_rekey->ctrl));
	CHECK(after_rekey->ctrl != NULL);
	after_rekey->ctrl->pvc_event = VTDTR_DEVICE_KILL;
	after_rekey->ctrl->pvc_pid = 123;
	after_rekey->ctrl->pvc_kill_vmid = 42;
	after_rekey->ctrl->pvc_kill_epoch = 99;
	after_rekey->ctrl->pvc_source_id[0] = 0x42;
	pci_vtdtr_cq_enqueue(sc.vsd_ctrlq, after_rekey);
	sc.vsd_guest_ready = 1;
	available = 3;
	before_stale = completions;
	pthread_cond_broadcast(&sc.vsd_cond);
	CHECK(clock_gettime(CLOCK_MONOTONIC, &until) == 0);
	until.tv_nsec += 50000000;
	if (until.tv_nsec >= 1000000000) {
		until.tv_nsec -= 1000000000;
		until.tv_sec++;
	}
	int wait_error;
	do {
		wait_error = pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until);
	} while (wait_error == 0);
	CHECK(wait_error == ETIMEDOUT);
	CHECK(!sc.vsd_rekey_wait && queue.count == 2 &&
	    completions == before_stale);
	CHECK(pthread_mutex_unlock(&sc.vsd_mtx) == 0);
	CHECK(pci_vtdtr_handoff_ticket_attach(&ticket_pi,
	    ticket_token, ticket_digest, NULL, 0) == 0);
	CHECK(pthread_mutex_lock(&sc.vsd_mtx) == 0);
	clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
	while (!sc.vsd_rekey_wait)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(queue.count == 1 && completions == before_stale + 1 &&
	    output.pvc_event == VTDTR_DEVICE_NODE_REKEY &&
	    sc.vsd_guest_ready == 0);
	sc.vsd_vs.vs_negotiated_caps |= VTDTR_WIRE_F_REKEY_RECEIPT_V1;
	uint8_t receipt_program[16] = { 1 }, receipt_source[16] = { 2 };
	uint8_t receipt_digest[32] = { 0x42 };
	dtraced_delivery_status_t rekey_status = { 0 };
	CHECK(pci_vtdtr_rekey_delivery_receipt(&sc, 0, 55,
	    receipt_program, receipt_source, receipt_digest,
	    &rekey_status) == 0 && rekey_status.phase == 'a');
	CHECK(pci_vtdtr_rekey_delivery_receipt(&sc, 3, 55,
	    receipt_program, receipt_source, receipt_digest,
	    &rekey_status) == 0 && rekey_status.phase == 'a' &&
	    handoff_live_queries == 2);
	handoff_phase = 't';
	handoff_revoked = 1;
	handoff_empty_digest = 1;
	CHECK(pci_vtdtr_rekey_delivery_receipt(&sc, 0, 55,
	    receipt_program, receipt_source, receipt_digest,
	    &rekey_status) == 0 && rekey_status.phase == 't' &&
	    rekey_status.revoked == 1 && rekey_status.digest[0] == 0);
	CHECK(pci_vtdtr_rekey_delivery_receipt(&sc, 3, 55,
	    receipt_program, receipt_source, receipt_digest,
	    &rekey_status) == EPROTO);
	handoff_phase = 'a';
	handoff_revoked = handoff_empty_digest = 0;
	CHECK(pci_vtdtr_rekey_kill_receipt(&sc, 3,
	    receipt_source, &rekey_status) == 0 &&
	    rekey_status.revoked == 1 && handoff_live_kills == 1);
	receipt_digest[0]++;
	CHECK(pci_vtdtr_rekey_delivery_receipt(&sc, 0, 55,
	    receipt_program, receipt_source, receipt_digest,
	    &rekey_status) == EPROTO);
	receipt_digest[0]--;
	handoff_bad_id = 1;
	CHECK(pci_vtdtr_rekey_delivery_receipt(&sc, 0, 55,
	    receipt_program, receipt_source, receipt_digest,
	    &rekey_status) == EPROTO);
	handoff_bad_id = 0;
	vm_epoch = 98;
	CHECK(pci_vtdtr_rekey_delivery_receipt(&sc, 0, 55,
	    receipt_program, receipt_source, receipt_digest,
	    &rekey_status) == ESTALE);
	vm_epoch = 99;
	const uint32_t rekey_queries[] = {
	    VTDTR_DEVICE_REKEY_DELIVERY_QUERY,
	    VTDTR_DEVICE_REKEY_INGRESS_QUERY,
	    VTDTR_DEVICE_REKEY_KILL_QUERY,
	    VTDTR_DEVICE_REKEY_DELIVERY_QUERY };
	const uint32_t rekey_replies[] = {
	    VTDTR_DEVICE_REKEY_DELIVERY_RECEIPT,
	    VTDTR_DEVICE_REKEY_INGRESS_RECEIPT,
	    VTDTR_DEVICE_REKEY_KILL_RECEIPT,
	    VTDTR_DEVICE_REKEY_DELIVERY_RECEIPT };
	for (size_t ri = 0; ri < nitems(rekey_queries); ri++) {
		if (ri == 3)
			handoff_error = ETIMEDOUT;
		struct pci_vtdtr_control receipt_query = {
		    .pvc_event = rekey_queries[ri] };
		receipt_query.pvc_installed_delivery_id = ri == 2 ? 3 : 55;
		receipt_query.pvc_installed_vmid = 41;
		receipt_query.pvc_installed_epoch = 98;
		receipt_query.pvc_installed_query_id = 100 + ri;
		receipt_query.pvc_installed_source_id[0] = 2;
		if (ri != 2) {
			receipt_query.pvc_installed_program_id[0] = 1;
			receipt_query.pvc_installed_digest[0] = 0x42;
		}
		struct iovec receipt_iov = { &receipt_query,
		    sizeof(receipt_query) };
		CHECK(pci_vtdtr_control_rx(&sc, &receipt_iov, 1) == 0 &&
		    sc.vsd_rekey_receipt_reply_pending && queue.count == 1);
		available = 1;
		before_stale = completions;
		pthread_cond_broadcast(&sc.vsd_cond);
		clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
		while (sc.vsd_rekey_receipt_reply_pending)
			CHECK(pthread_cond_timedwait(&sc.vsd_cond,
			    &sc.vsd_mtx, &until) == 0);
		CHECK(output.pvc_event == rekey_replies[ri] &&
		    output.pvc_installed_delivery_id ==
		    receipt_query.pvc_installed_delivery_id &&
		    output.pvc_installed_vmid == 41 &&
		    output.pvc_installed_epoch == 98 &&
		    output.pvc_installed_query_id == 100 + ri &&
		    output.pvc_installed_phase == (ri == 3 ? 'u' : 'a') &&
		    (ri != 3 || output.pvc_installed_digest[0] == 0) &&
		    completions == before_stale + 1 && queue.count == 1);
		handoff_error = 0;
	}
	CHECK(pci_vtdtr_checkpoint_state_valid(&sc) == EBUSY);
	struct iovec ready_iov = { &ready, sizeof(ready) };
	CHECK(pci_vtdtr_control_rx(&sc, &ready_iov, 1) == 0);
	CHECK(sc.vsd_rekey_wait && sc.vsd_guest_ready == 0 &&
	    queue.count == 1);
	struct pci_vtdtr_control commit = { .pvc_event =
	    VTDTR_DEVICE_REKEY_COMMIT, .pvc_rekey_old_id = 41,
	    .pvc_rekey_old_epoch = 98, .pvc_rekey_new_id = 42,
	    .pvc_rekey_new_epoch = 99 };
	struct iovec commit_iov = { &commit, sizeof(commit) };
	CHECK(pci_vtdtr_control_rx(&sc, &commit_iov, 1) == 0 &&
	    sc.vsd_rekey_ack_pending && queue.count == 1);
	CHECK(pci_vtdtr_rekey_delivery_receipt(&sc, 0, 55,
	    receipt_program, receipt_source, receipt_digest,
	    &rekey_status) == ESTALE);
	available = 1;
	before_stale = completions;
	pthread_cond_broadcast(&sc.vsd_cond);
	clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
	while (!sc.vsd_rekey_ack_sent)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(!sc.vsd_rekey_ack_pending && sc.vsd_rekey_wait &&
	    queue.count == 1 && completions == before_stale + 1 &&
	    output.pvc_event == VTDTR_DEVICE_REKEY_COMMITTED &&
	    output.pvc_rekey_old_id == 41 &&
	    output.pvc_rekey_old_epoch == 98 &&
	    output.pvc_rekey_new_id == 42 &&
	    output.pvc_rekey_new_epoch == 99);
	CHECK(pci_vtdtr_control_rx(&sc, &commit_iov, 1) == 0 &&
	    !sc.vsd_rekey_ack_pending);
	CHECK(pci_vtdtr_control_rx(&sc, &ready_iov, 1) == 0 &&
	    sc.vsd_rekey_wait && !sc.vsd_guest_ready && queue.count == 1);
	struct pci_vtdtr_control rekey_applied = commit;
	rekey_applied.pvc_event = VTDTR_DEVICE_REKEY_APPLIED;
	struct iovec rekey_applied_iov = { &rekey_applied,
	    sizeof(rekey_applied) };
	CHECK(pci_vtdtr_control_rx(&sc, &rekey_applied_iov, 1) == 0 &&
	    !sc.vsd_rekey_wait && sc.vsd_guest_ready &&
	    rekey_applied_calls == 1 &&
	    !sc.vsd_handoff_ticket_valid &&
	    !sc.vsd_rekey_ack_pending && !sc.vsd_rekey_ack_sent &&
	    sc.vsd_rekey_old_id == 0 && sc.vsd_rekey_new_id == 0 &&
	    sc.vsd_rekey_old_epoch == 0 && sc.vsd_rekey_new_epoch == 0 &&
	    sc.vsd_handoff_token[0] == 0);
	available = 1;
	pthread_cond_broadcast(&sc.vsd_cond);
	clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
	while (queue.count != 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(output.pvc_event == VTDTR_DEVICE_KILL &&
	    output.pvc_kill_vmid == 42 && output.pvc_kill_epoch == 99);
	pci_vtdtr_reset(&sc);
	sc.vsd_rekey_wait = true;
	sc.vsd_rekey_old_id = 41;
	sc.vsd_rekey_old_epoch = 98;
	sc.vsd_rekey_new_id = 42;
	sc.vsd_rekey_new_epoch = 99;
	sc.vsd_handoff_ticket_valid = true;
	memcpy(sc.vsd_handoff_token, ticket_token, sizeof(ticket_token));
	memcpy(sc.vsd_handoff_digest, ticket_digest,
	    sizeof(ticket_digest));
	CHECK(clock_gettime(CLOCK_MONOTONIC,
	    &sc.vsd_rekey_deadline) == 0);
	sc.vsd_rekey_deadline.tv_sec += 60;
	struct pci_vtdtr_control bad_receipt_query = {
	    .pvc_event = VTDTR_DEVICE_REKEY_DELIVERY_QUERY };
	bad_receipt_query.pvc_installed_delivery_id = 55;
	bad_receipt_query.pvc_installed_vmid = 41;
	bad_receipt_query.pvc_installed_epoch = 97;
	bad_receipt_query.pvc_installed_query_id = 901;
	bad_receipt_query.pvc_installed_program_id[0] = 1;
	bad_receipt_query.pvc_installed_source_id[0] = 2;
	bad_receipt_query.pvc_installed_digest[0] = 0x42;
	struct iovec bad_receipt_iov = { &bad_receipt_query,
	    sizeof(bad_receipt_query) };
	CHECK(pci_vtdtr_control_rx(&sc, &bad_receipt_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 &&
	    !sc.vsd_rekey_wait && !sc.vsd_handoff_ticket_valid &&
	    !sc.vsd_rekey_receipt_reply_pending);
	pci_vtdtr_reset(&sc);
	sc.vsd_rekey_wait = true;
	/* An expired barrier must quarantine the stopped queue even without
	 * another guest descriptor or daemon event. */
	CHECK(clock_gettime(CLOCK_MONOTONIC,
	    &sc.vsd_rekey_deadline) == 0);
	sc.vsd_rekey_deadline.tv_sec--;
	pthread_cond_broadcast(&sc.vsd_cond);
	clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
	while ((sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(!sc.vsd_rekey_wait && queue.count == 0);
	pci_vtdtr_reset(&sc);
	struct pci_vtdtr_ctrl_entry *ticketless = calloc(1,
	    sizeof(*ticketless));
	CHECK(ticketless != NULL);
	ticketless->ctrl = calloc(1, sizeof(*ticketless->ctrl));
	CHECK(ticketless->ctrl != NULL);
	ticketless->ctrl->pvc_event = VTDTR_DEVICE_NODE_REKEY;
	pci_vtdtr_cq_enqueue(sc.vsd_ctrlq, ticketless);
	sc.vsd_guest_ready = 1;
	available = 1;
	before_stale = completions;
	sc.vsd_ticket_wait = true;
	CHECK(clock_gettime(CLOCK_MONOTONIC,
	    &sc.vsd_ticket_deadline) == 0);
	sc.vsd_ticket_deadline.tv_sec--;
	pthread_cond_broadcast(&sc.vsd_cond);
	clock_gettime(CLOCK_MONOTONIC, &until); until.tv_sec += 2;
	while ((sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(!sc.vsd_ticket_wait && queue.count == 0 &&
	    completions == before_stale);
	pci_vtdtr_reset(&sc);
	sc.vsd_rekey_wait = true;
	CHECK(clock_gettime(CLOCK_MONOTONIC,
	    &sc.vsd_rekey_deadline) == 0);
	sc.vsd_rekey_deadline.tv_sec += 60;
	sc.vsd_rekey_old_id = 41;
	sc.vsd_rekey_old_epoch = 98;
	sc.vsd_rekey_new_id = 42;
	sc.vsd_rekey_new_epoch = 99;
	commit.pvc_rekey_old_epoch = 97;
	CHECK(pci_vtdtr_control_rx(&sc, &commit_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 &&
	    !sc.vsd_rekey_wait && queue.count == 0);
	pci_vtdtr_reset(&sc);
	sc.vsd_rekey_wait = true;
	CHECK(clock_gettime(CLOCK_MONOTONIC,
	    &sc.vsd_rekey_deadline) == 0);
	sc.vsd_rekey_deadline.tv_sec += 60;
	struct pci_vtdtr_control premature_elf = {
	    .pvc_event = VTDTR_DEVICE_ELF,
	};
	struct iovec premature_iov = { &premature_elf, sizeof(premature_elf) };
	CHECK(pci_vtdtr_control_rx(&sc, &premature_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 &&
	    queue.count == 0);
	pci_vtdtr_reset(&sc);
	sc.vsd_rekey_wait = true;
	sc.vsd_rekey_ack_sent = true;
	CHECK(clock_gettime(CLOCK_MONOTONIC,
	    &sc.vsd_rekey_deadline) == 0);
	sc.vsd_rekey_deadline.tv_sec += 60;
	sc.vsd_rekey_old_id = 41;
	sc.vsd_rekey_old_epoch = 98;
	sc.vsd_rekey_new_id = 42;
	sc.vsd_rekey_new_epoch = 99;
	rekey_applied.pvc_rekey_old_epoch = 97;
	CHECK(pci_vtdtr_control_rx(&sc, &rekey_applied_iov, 1) == 1 &&
	    (sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0 &&
	    !sc.vsd_rekey_wait && queue.count == 0);
	pci_vtdtr_reset(&sc);
	CHECK(!sc.vsd_rekey_wait && queue.count == 0);
	pthread_mutex_unlock(&sc.vsd_mtx);
	struct pci_vtdtr_control unsupported = { .pvc_event =
	    VTDTR_DEVICE_REGISTER };
	CHECK(!pci_vtdtr_ctrl_matches_vm(&unsupported, 42, 99));
	unsupported.pvc_event = VTDTR_DEVICE_READY;
	CHECK(pci_vtdtr_ctrl_matches_vm(&unsupported, 42, 99));
	sc.vsd_communicator = worker;
	pthread_mutex_lock(&sc.vsd_mtx);
	pci_vtdtr_reset(&sc);
	pthread_mutex_unlock(&sc.vsd_mtx);
	injected_header = (dtraced_hdr_t){ .msg_type = DTRACED_MSG_KILL };
	injected_header.kill.pid = 123;
	injected_header.kill.vmid = 42;
	injected_header.kill.epoch = 98;
	injected_header.kill.source_id[0] = 0x42;
	injected_generation = sc.vsd_generation;
	atomic_store_explicit(&injected_frame, 1, memory_order_release);
	CHECK(pthread_create(&sc.vsd_reader, NULL, pci_vtdtr_events, &sc) == 0);
	pthread_mutex_lock(&sc.vsd_mtx);
	clock_gettime(CLOCK_MONOTONIC, &until);
	until.tv_sec += 2;
	while ((sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) == 0)
		CHECK(pthread_cond_timedwait(&sc.vsd_cond,
		    &sc.vsd_mtx, &until) == 0);
	CHECK(queue.count == 0);
	pthread_mutex_unlock(&sc.vsd_mtx);
	pci_vtdtr_stop_workers(&sc);
	CHECK(sc.vsd_stopping);
	installed.pvc_installed_epoch = 98;
	pthread_mutex_lock(&sc.vsd_mtx);
	CHECK(pci_vtdtr_control_rx(&sc, &installed_iov, 1) != 0);
	CHECK(sc.vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET);
	pthread_mutex_unlock(&sc.vsd_mtx);
	pthread_cond_destroy(&sc.vsd_cond);
	pthread_mutex_destroy(&sc.vsd_mtx);
	/* Exercise successful device initialization and its registered shutdown. */
	struct pci_devinst pi = { 0 };
	CHECK(pci_vtdtr_init(&pi, NULL) == 0);
	CHECK(vtdtr_present && vtdtr_shutdown_sc != NULL);
	struct pci_vtdtr_softc *live = vtdtr_shutdown_sc;
	CHECK(pi.pi_arg == &live->vsd_vs);
	pci_vtdtr_shutdown();
	CHECK(vtdtr_shutdown_sc == NULL && live->vsd_stopping);
	struct pci_vtdtr_control late_ready = { .pvc_event = VTDTR_DEVICE_READY };
	struct iovec late_ready_iov = { &late_ready, sizeof(late_ready) };
	int writes_after_stop = writes;
	pthread_mutex_lock(&live->vsd_mtx);
	CHECK(live->vsd_guest_ready == 0);
	CHECK(pci_vtdtr_control_rx(live, &late_ready_iov, 1) == 1);
	CHECK(live->vsd_guest_ready == 0 &&
	    (live->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	CHECK(writes == writes_after_stop);
	available = 1;
	pci_vtdtr_notify_rx(live, &live->vsd_queues[1]);
	CHECK(available == 1 && writes == writes_after_stop);
	available = 0;
	int resets_after_stop = reset_calls;
	pci_vtdtr_reset(live);
	CHECK(reset_calls == resets_after_stop && live->vsd_stopping &&
	    (live->vsd_vs.vs_status & VIRTIO_CONFIG_S_NEEDS_RESET) != 0);
	pthread_mutex_unlock(&live->vsd_mtx);
	pci_vtdtr_shutdown();
	pci_vtdtr_reset_queue(live);
	hypertrace_elf_reset(&live->vsd_inbound_elf);
	pthread_mutex_destroy(&live->vsd_vs.vs_isr_mtx);
	pthread_cond_destroy(&live->vsd_cond);
	pthread_mutex_destroy(&live->vsd_mtx);
	free(live->vsd_ctrlq);
	free(live);
	pi.pi_arg = NULL;
	puts("PASS: device callback locking, reset cleanup and stale publication rejection, descriptor backpressure, worker wakeup");
	return (0);
}
