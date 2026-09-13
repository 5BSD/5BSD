/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Durable installation identities, sources, and transaction history.
 * All operations require a locked transaction; publication is atomic and synced.
 */
#ifndef SWITCHBOARD_LIFECYCLE_H
#define SWITCHBOARD_LIFECYCLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SL_DIRECTORY "/Capabilities/Config/switchboard/lifecycle"
#define SL_MAX_RECORDS 262144
#define SL_HISTORY_KEEP 256
#define SL_LABEL_MAX 64
#define SL_GENERATION_SIZE 16
#define SL_SOURCE_MAX 256

enum sl_phase { SL_ACTIVE = 1, SL_PREPARED, SL_RETIRED, SL_COMPLETE, SL_INSTALLING };
enum sl_kind { SL_OWNER = 1, SL_PROVIDER, SL_DELIVERY, SL_OPERATION, SL_REFERENCE, SL_HOLDING, SL_POLICY, SL_TICKET };
struct sl_record {
	uint32_t kind;
	uint32_t phase;
	char label[SL_LABEL_MAX];
	char provider[SL_LABEL_MAX]; /* OWNER: resource key; DELIVERY: provider label */
	uint8_t generation[SL_GENERATION_SIZE];
	char reference[SL_LABEL_MAX];
	char source[SL_SOURCE_MAX]; /* OPERATION/REFERENCE: installer provenance */
};
struct sl_db {
	int dirfd;
	int lockfd;
	struct sl_record *records;
	size_t count;
	bool dirty;
	bool has_state;
	bool readonly;
};

enum sl_operation_phase {
	SL_INSTALL_PENDING = 10, SL_INSTALL_COMMITTED, SL_INSTALL_CANCELLED,
	SL_REMOVE_PENDING = 20, SL_REMOVE_COMMITTED, SL_REMOVE_CANCELLED
};
enum sl_reference_phase { SL_REF_STAGED, SL_REF_LIVE, SL_REF_REMOVED };
struct sl_record *sl_operation(struct sl_db *, const char *, const char *);
int sl_install_begin(struct sl_db *, const char *, const char *, const char *);
int sl_install_finish(struct sl_db *, const char *, const char *, bool);
int sl_remove_begin(struct sl_db *, const char *, const char *, const char *);
int sl_remove_finish(struct sl_db *, const char *, const char *, bool);

/* These are installation facts, independent of provider cleanup receipts. */
enum sl_installation_state {
	SL_UNKNOWN = 0, SL_INSTALLED, SL_INSTALL_IN_PROGRESS,
	SL_REMOVE_IN_PROGRESS, SL_REMOVED
};
struct sl_installation {
	enum sl_installation_state state;
	uint32_t live_sources;
	uint32_t staged_sources;
	uint8_t generation[SL_GENERATION_SIZE];
};
int sl_query(struct sl_db *, const char *, const uint8_t *, struct sl_installation *);
const char *sl_state_name(enum sl_installation_state);
int sl_record_source(struct sl_db *, const char *, const char *, const char *);
/* Issue before starting work; persist before handing the ID to another process. */
int sl_issue_operation(struct sl_db *, char [33]);
/* Retain current state, pending work, and recent completed operations. */
int sl_prune_history(struct sl_db *, size_t, size_t *);
int sl_open(const char *, struct sl_db *);
/* Runtime mutation: existing store/lock only; never wait behind an installer. */
int sl_open_update(const char *, struct sl_db *);
/* Existing store only; never creates records. EWOULDBLOCK if a writer holds it. */
int sl_open_readonly(const char *, struct sl_db *);
/* Single-threaded reader; retains one validated snapshot, never a lock.
 * Revalidates trust, file identity and vnode events on every query.
 * Destroy when no longer needed. Errors return UNKNOWN, never stale facts. */
struct sl_query_cache;
struct sl_query_cache *sl_query_cache_create(void);
void sl_query_cache_destroy(struct sl_query_cache *);
/* Changes after each successful snapshot rebuild; inspect only after a read. */
uint64_t sl_query_cache_revision(const struct sl_query_cache *);
bool sl_query_cache_cleanup_pending(const struct sl_query_cache *);
int sl_query_cached(struct sl_query_cache *, const char *, const char *,
    const uint8_t *, struct sl_installation *);
/* Runtime admission uses the owner phase: a pending non-last-source removal
 * still admits sessions. Outputs remain unchanged on error. The expected ID
 * may alias the output generation; a missing exact incarnation is ESTALE. */
int sl_query_cached_active(struct sl_query_cache *, const char *, const char *,
    const uint8_t *, uint8_t *, char [SL_LABEL_MAX]);
/* Visit owners whose phase requires stopping that incarnation. A pending
 * removal of only one source does not qualify. Callback must not mutate the
 * store or reuse the cache; the shared transaction lock is held until return. */
int sl_query_cached_retired(struct sl_query_cache *, const char *,
    void (*)(const char *, const uint8_t *, void *), void *);
/* After any failed mutation, close without committing the transaction. */
int sl_commit(struct sl_db *);
void sl_close(struct sl_db *);
bool sl_label_valid(const char *);
bool sl_generation_valid(const uint8_t *);
struct sl_record *sl_owner(struct sl_db *, const char *);
/* Explicit installer migration only; runtime discovery must never adopt. */
int sl_adopt(struct sl_db *, const char *, uint8_t *);
int sl_install(struct sl_db *, const char *, uint8_t *);
struct sl_record *sl_generation(struct sl_db *, const char *, const uint8_t *);
int sl_prepare(struct sl_db *, const char *, uint8_t *);
int sl_retire(struct sl_db *, const char *, const uint8_t *);
bool sl_blocked(struct sl_db *, const char *);
int sl_generation_parse(const char *, uint8_t *);
void sl_generation_format(const uint8_t *, char [33]);

#endif
