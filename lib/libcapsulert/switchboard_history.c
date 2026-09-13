/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Bounded diagnostic history, independent of provider cleanup policy.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "switchboard_lifecycle.h"
#include "switchboard_lifecycle_private.h"
#include "switchboard_reclamation.h"

bool
sl_history_strict(struct sl_db *db)
{
	for (size_t i = 0; i < db->count; i++)
		if (db->records[i].kind == SL_POLICY)
			return (true);
	return (false);
}

bool
sl_operation_issued(struct sl_db *db, const char *operation)
{
	for (size_t i = 0; i < db->count; i++)
		if (db->records[i].kind == SL_TICKET &&
		    strcmp(db->records[i].provider, operation) == 0)
			return (true);
	return (false);
}

int
sl_issue_operation(struct sl_db *db, char operation[33])
{
	struct sl_record *r;
	uint8_t nonce[16];

	if (db->readonly)
		return (errno = EROFS, -1);
	do {
		arc4random_buf(nonce, sizeof(nonce));
		sl_generation_format(nonce, operation);
	} while (!sl_generation_valid(nonce) || sl_operation_issued(db, operation));
	r = sl_append(db);
	if (r == NULL)
		return (-1);
	r->kind = SL_TICKET;
	strlcpy(r->label, "authority.operation", sizeof(r->label));
	strlcpy(r->provider, operation, sizeof(r->provider));
	memcpy(r->generation, nonce, sizeof(nonce));
	return (0);
}

bool
sl_history_due(struct sl_db *db)
{
	size_t finished = 0, tickets = 0;

	for (size_t i = 0; i < db->count; i++) {
		struct sl_record *r = &db->records[i];
		if (r->kind == SL_OPERATION && r->phase != SL_INSTALL_PENDING &&
		    r->phase != SL_REMOVE_PENDING)
			finished++;
		tickets += r->kind == SL_TICKET;
	}
	return (finished > SL_HISTORY_KEEP || tickets > 2 * SL_HISTORY_KEEP);
}

struct history_index { const struct sl_record *r; size_t position; };

static int
history_compare(const void *va, const void *vb)
{
	const struct sl_record *a = ((const struct history_index *)va)->r;
	const struct sl_record *b = ((const struct history_index *)vb)->r;
	int cmp;

	if (a->kind != b->kind)
		return (a->kind < b->kind ? -1 : 1);
	if (a->kind == SL_TICKET)
		return (strcmp(a->provider, b->provider));
	cmp = strcmp(a->label, b->label);
	if (cmp != 0)
		return (cmp);
	cmp = memcmp(a->generation, b->generation, SL_GENERATION_SIZE);
	if (cmp != 0 || a->kind == SL_OWNER)
		return (cmp);
	return (strcmp(a->reference, b->reference));
}

/* Keep the most recent matching row, as the transaction reader does. */
static void
history_mark(struct history_index *index, size_t count, bool *keep,
    uint32_t kind, const struct sl_record *record)
{
	struct sl_record key = *record;
	struct history_index needle = { .r = &key }, *found, *last;
	size_t newest;

	key.kind = kind;
	found = bsearch(&needle, index, count, sizeof(*index), history_compare);
	if (found == NULL)
		return;
	while (found > index && history_compare(&needle, found - 1) == 0)
		found--;
	newest = found->position;
	for (last = found + 1; last < index + count &&
	    history_compare(&needle, last) == 0; last++)
		if (last->position > newest)
			newest = last->position;
	keep[newest] = true;
}

static struct history_index *
history_ticket(struct history_index *index, size_t count,
    const struct sl_record *record)
{
	struct sl_record key = { .kind = SL_TICKET };
	struct history_index needle = { .r = &key };

	strlcpy(key.provider, record->provider, sizeof(key.provider));
	return (bsearch(&needle, index, count, sizeof(*index), history_compare));
}

int
sl_prune_history(struct sl_db *db, size_t retain, size_t *removed)
{
	struct history_index *index;
	struct sl_record *r;
	bool *keep;
	size_t recent = 0, output = 0, discarded = 0, original = db->count;

	if (removed != NULL)
		*removed = 0;
	if (db->readonly)
		return (errno = EROFS, -1);
	if (retain == 0 || retain > SL_MAX_RECORDS)
		return (errno = EINVAL, -1);
	/* Reserve the policy row after compaction, so a full legacy store can
	 * reclaim expired rows before it needs space for the rejection fence. */
	index = calloc(db->count == 0 ? 1 : db->count, sizeof(*index));
	keep = calloc(db->count == 0 ? 1 : db->count, sizeof(*keep));
	if (index == NULL || keep == NULL) {
		free(index);
		free(keep);
		return (-1);
	}
	for (size_t i = 0; i < db->count; i++) {
		index[i].r = &db->records[i];
		index[i].position = i;
	}
	qsort(index, db->count, sizeof(*index), history_compare);
	/* One last-known owner per label prevents implicit resurrection after expiry. */
	for (size_t i = 0; i < db->count;) {
		size_t next = i + 1, newest = index[i].position;
		if (index[i].r->kind != SL_OWNER) {
			i++;
			continue;
		}
		while (next < db->count && index[next].r->kind == SL_OWNER &&
		    strcmp(index[next].r->label, index[i].r->label) == 0) {
			if (index[next].position > newest)
				newest = index[next].position;
			next++;
		}
		keep[newest] = true;
		i = next;
	}
	for (size_t i = db->count; i != 0; i--) {
		r = &db->records[i - 1];
		switch (r->kind) {
		case SL_OPERATION:
			keep[i - 1] = r->phase == SL_INSTALL_PENDING ||
			    r->phase == SL_REMOVE_PENDING ||
			    (history_ticket(index, db->count, r) == NULL && recent++ < retain);
			break;
		case SL_TICKET:
			/* Also preserve recent, issued-but-unused operations. */
			keep[i - 1] = recent++ < retain;
			break;
		case SL_REFERENCE:
			keep[i - 1] = r->phase != SL_REF_REMOVED;
			break;
		case SL_OWNER:
			keep[i - 1] |= r->phase == SL_ACTIVE || r->phase == SL_INSTALLING ||
			    r->phase == SL_PREPARED || r->phase == SL_RETIRED ||
			    (r->phase == SL_COMPLETE &&
			    strcmp(r->reference, SL_CLEANUP_COMPLETE) != 0);
			break;
		case SL_HOLDING:
		case SL_DELIVERY: {
			struct sl_record key = *r;
			key.kind = SL_OWNER;
			struct history_index needle = { .r = &key };
			struct history_index *found = bsearch(&needle, index, db->count,
			    sizeof(*index), history_compare);
			const struct sl_record *owner = found != NULL ? found->r : NULL;
			if (found != NULL) {
				while (found > index && history_compare(&needle, found - 1) == 0)
					found--;
				for (; found < index + db->count &&
				    history_compare(&needle, found) == 0; found++)
					if (found->r->phase != SL_COMPLETE ||
					    strcmp(found->r->reference, SL_CLEANUP_COMPLETE) != 0) {
						owner = found->r;
						break;
					}
			}
			/* Pending cleanup is durable work, not disposable history. */
			keep[i - 1] = owner == NULL || owner->phase != SL_COMPLETE ||
			    strcmp(owner->reference, SL_CLEANUP_COMPLETE) != 0;
			break;
		}
		default:
			keep[i - 1] = true;
			break;
		}
	}
	/* Retain whole issued transactions: never forget one label while its ID
	 * could still authorize starting another label in the same package run. */
	for (size_t i = 0; i < db->count; i++)
		if (keep[i] && db->records[i].kind == SL_OPERATION)
			history_mark(index, db->count, keep, SL_TICKET, &db->records[i]);
	for (size_t i = 0; i < db->count; i++) {
		if (db->records[i].kind != SL_OPERATION)
			continue;
		struct history_index *ticket = history_ticket(index, db->count,
		    &db->records[i]);
		if (ticket != NULL && keep[ticket->position])
			keep[i] = true;
	}
	/* Preserve dependencies of retained history and unfinished work. */
	for (size_t i = 0; i < db->count; i++) {
		r = &db->records[i];
		if (!keep[i])
			continue;
		if (r->kind == SL_OPERATION) {
			history_mark(index, db->count, keep, SL_REFERENCE, r);
			history_mark(index, db->count, keep, SL_TICKET, r);
		}
		if (r->kind == SL_OPERATION || r->kind == SL_REFERENCE ||
		    r->kind == SL_HOLDING || r->kind == SL_DELIVERY)
			history_mark(index, db->count, keep, SL_OWNER, r);
	}
	/* Completed receipts/holdings follow the bounded owner history. */
	for (size_t i = 0; i < db->count; i++) {
		r = &db->records[i];
		if (r->kind != SL_HOLDING && r->kind != SL_DELIVERY)
			continue;
		struct sl_record key = *r;
		key.kind = SL_OWNER;
		struct history_index needle = { .r = &key };
		struct history_index *owner = bsearch(&needle, index, db->count,
		    sizeof(*index), history_compare);
		if (owner != NULL) {
			while (owner > index && history_compare(&needle, owner - 1) == 0)
				owner--;
			for (; owner < index + db->count &&
			    history_compare(&needle, owner) == 0; owner++)
				keep[i] |= keep[owner->position];
		}
	}
	free(index);
	for (size_t i = 0; i < db->count; i++) {
		if (keep[i])
			db->records[output++] = db->records[i];
		else if (i < original)
			discarded++;
	}
	free(keep);
	if (output != db->count)
		db->dirty = true;
	db->count = output;
	/* The fence and discarded history are still one atomic committed image. */
	if (!sl_history_strict(db)) {
		r = sl_append(db);
		if (r == NULL)
			return (-1);
		r->kind = SL_POLICY;
		strlcpy(r->label, "authority.policy", sizeof(r->label));
	}
	if (removed != NULL)
		*removed = discarded;
	return (0);
}
