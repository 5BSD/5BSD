/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - Decision Cache
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/sdt.h>

#include <security/oes/oes.h>
#include <security/oes/oes_internal.h>

MALLOC_DECLARE(M_OES);

/* DTrace probes defined in oes_event.c */
SDT_PROBE_DECLARE(oes, , , cache__hit);
SDT_PROBE_DECLARE(oes, , , cache__miss);

static __inline bool
oes_cache_proc_equal(const oes_proc_token_t *a, const oes_proc_token_t *b)
{
	return (a->ept_id == b->ept_id && a->ept_genid == b->ept_genid);
}

static __inline bool
oes_cache_file_equal(const oes_file_token_t *a, const oes_file_token_t *b)
{
	return (a->eft_id == b->eft_id && a->eft_dev == b->eft_dev);
}

static __inline bool
oes_cache_file_valid(const oes_file_token_t *tok)
{
	return (tok->eft_id != 0 || tok->eft_dev != 0);
}

static __inline bool
oes_cache_proc_valid(const oes_proc_token_t *tok)
{
	return (tok->ept_id != 0 && tok->ept_genid != 0);
}

static bool
oes_cache_event_requires_target(oes_event_type_t event)
{
	switch (event) {
	case OES_EVENT_AUTH_UNLINK:
	case OES_EVENT_AUTH_RENAME:
	case OES_EVENT_AUTH_LINK:
		return (true);
	default:
		return (false);
	}
}

static uint32_t
oes_cache_bucket(oes_event_type_t event)
{
	return ((uint32_t)event & (OES_CACHE_BUCKETS - 1));
}

static void
oes_cache_make_deadline(struct timespec *deadline, uint32_t ttl_ms)
{
	struct timespec now;
	struct timespec ts;

	nanouptime(&now);
	ts.tv_sec = ttl_ms / 1000;
	ts.tv_nsec = (ttl_ms % 1000) * 1000000;
	timespecadd(&now, &ts, deadline);
}

static bool
oes_cache_key_equal(const oes_cache_key_t *a, const oes_cache_key_t *b)
{
	if (a->eck_event != b->eck_event)
		return (false);
	if (a->eck_flags != b->eck_flags)
		return (false);
	if (a->eck_op_flags != b->eck_op_flags)
		return (false);
	if ((a->eck_flags & OES_CACHE_KEY_PROCESS) &&
	    !oes_cache_proc_equal(&a->eck_process, &b->eck_process))
		return (false);
	if ((a->eck_flags & OES_CACHE_KEY_FILE) &&
	    !oes_cache_file_equal(&a->eck_file, &b->eck_file))
		return (false);
	if ((a->eck_flags & OES_CACHE_KEY_TARGET) &&
	    !oes_cache_file_equal(&a->eck_target, &b->eck_target))
		return (false);
	return (true);
}

static bool
oes_cache_key_match_remove(const oes_cache_key_t *entry,
    const oes_cache_key_t *remove)
{
	if (remove->eck_event != OES_CACHE_EVENT_ANY &&
	    entry->eck_event != remove->eck_event)
		return (false);
	if ((remove->eck_flags & OES_CACHE_KEY_PROCESS) != 0) {
		if ((entry->eck_flags & OES_CACHE_KEY_PROCESS) == 0)
			return (false);
		if (!oes_cache_proc_equal(&entry->eck_process,
		    &remove->eck_process))
			return (false);
	}
	if ((remove->eck_flags & OES_CACHE_KEY_FILE) != 0) {
		if ((entry->eck_flags & OES_CACHE_KEY_FILE) == 0)
			return (false);
		if (!oes_cache_file_equal(&entry->eck_file, &remove->eck_file))
			return (false);
	}
	if ((remove->eck_flags & OES_CACHE_KEY_TARGET) != 0) {
		if ((entry->eck_flags & OES_CACHE_KEY_TARGET) == 0)
			return (false);
		if (!oes_cache_file_equal(&entry->eck_target,
		    &remove->eck_target))
			return (false);
	}
	return (true);
}

static bool
oes_cache_key_from_pending(const struct oes_pending *ep,
    oes_cache_key_t *key)
{
	const oes_message_t *msg;
	oes_file_token_t file = { 0 };
	oes_file_token_t target = { 0 };

	msg = &ep->ep_msg;
	if (!OES_EVENT_IS_AUTH(msg->em_event))
		return (false);

	bzero(key, sizeof(*key));
	key->eck_event = msg->em_event;
	key->eck_flags = OES_CACHE_KEY_PROCESS;
	key->eck_process = msg->em_process.ep_token;
	if (!oes_cache_proc_valid(&key->eck_process))
		return (false);

	switch (msg->em_event) {
	case OES_EVENT_AUTH_EXEC:
		file = msg->em_event_data.exec.executable.ef_token;
		break;
	case OES_EVENT_AUTH_OPEN:
		file = msg->em_event_data.open.file.ef_token;
		key->eck_op_flags = (uint32_t)msg->em_event_data.open.flags;
		break;
	case OES_EVENT_AUTH_ACCESS:
		file = msg->em_event_data.access.file.ef_token;
		key->eck_op_flags = (uint32_t)msg->em_event_data.access.accmode;
		break;
	case OES_EVENT_AUTH_READ:
	case OES_EVENT_AUTH_WRITE:
		file = msg->em_event_data.rw.file.ef_token;
		break;
	case OES_EVENT_AUTH_STAT:
		file = msg->em_event_data.stat.file.ef_token;
		break;
	case OES_EVENT_AUTH_POLL:
		file = msg->em_event_data.poll.file.ef_token;
		break;
	case OES_EVENT_AUTH_REVOKE:
		file = msg->em_event_data.revoke.file.ef_token;
		break;
	case OES_EVENT_AUTH_READDIR:
		file = msg->em_event_data.readdir.dir.ef_token;
		break;
	case OES_EVENT_AUTH_READLINK:
		file = msg->em_event_data.readlink.file.ef_token;
		break;
	case OES_EVENT_AUTH_LOOKUP:
		file = msg->em_event_data.lookup.dir.ef_token;
		break;
	case OES_EVENT_AUTH_CREATE:
		/* Can't cache CREATE - file doesn't exist, key would collapse */
		return (false);
	case OES_EVENT_AUTH_UNLINK:
		file = msg->em_event_data.unlink.file.ef_token;
		target = msg->em_event_data.unlink.dir.ef_token;
		break;
	case OES_EVENT_AUTH_RENAME:
		file = msg->em_event_data.rename.src_file.ef_token;
		target = msg->em_event_data.rename.dst_dir.ef_token;
		break;
	case OES_EVENT_AUTH_LINK:
		file = msg->em_event_data.link.target.ef_token;
		target = msg->em_event_data.link.dir.ef_token;
		break;
	case OES_EVENT_AUTH_MOUNT:
		file = msg->em_event_data.mount.mountpoint.ef_token;
		break;
	case OES_EVENT_AUTH_KLDLOAD:
		file = msg->em_event_data.kldload.file.ef_token;
		break;
	case OES_EVENT_AUTH_MMAP:
		file = msg->em_event_data.mmap.file.ef_token;
		key->eck_op_flags = (uint32_t)msg->em_event_data.mmap.prot;
		break;
	case OES_EVENT_AUTH_MPROTECT:
		file = msg->em_event_data.mprotect.file.ef_token;
		key->eck_op_flags = (uint32_t)msg->em_event_data.mprotect.prot;
		break;
	case OES_EVENT_AUTH_CHDIR:
		file = msg->em_event_data.chdir.dir.ef_token;
		break;
	case OES_EVENT_AUTH_CHROOT:
		file = msg->em_event_data.chroot.dir.ef_token;
		break;
	case OES_EVENT_AUTH_SETEXTATTR:
		file = msg->em_event_data.setextattr.file.ef_token;
		break;
	case OES_EVENT_AUTH_GETEXTATTR:
		file = msg->em_event_data.getextattr.file.ef_token;
		break;
	case OES_EVENT_AUTH_DELETEEXTATTR:
		file = msg->em_event_data.deleteextattr.file.ef_token;
		break;
	case OES_EVENT_AUTH_LISTEXTATTR:
		file = msg->em_event_data.listextattr.file.ef_token;
		break;
	case OES_EVENT_AUTH_GETACL:
		file = msg->em_event_data.getacl.file.ef_token;
		break;
	case OES_EVENT_AUTH_SETACL:
		file = msg->em_event_data.setacl.file.ef_token;
		break;
	case OES_EVENT_AUTH_DELETEACL:
		file = msg->em_event_data.deleteacl.file.ef_token;
		break;
	case OES_EVENT_AUTH_RELABEL:
		file = msg->em_event_data.relabel.file.ef_token;
		break;
	case OES_EVENT_AUTH_SETMODE:
		file = msg->em_event_data.setmode.file.ef_token;
		break;
	case OES_EVENT_AUTH_SETOWNER:
		file = msg->em_event_data.setowner.file.ef_token;
		break;
	case OES_EVENT_AUTH_SETFLAGS:
		file = msg->em_event_data.setflags.file.ef_token;
		break;
	case OES_EVENT_AUTH_SETUTIMES:
		file = msg->em_event_data.setutimes.file.ef_token;
		break;
	case OES_EVENT_AUTH_SWAPON:
		file = msg->em_event_data.swapon.file.ef_token;
		break;
	case OES_EVENT_AUTH_SWAPOFF:
		file = msg->em_event_data.swapoff.file.ef_token;
		break;
	case OES_EVENT_AUTH_PTRACE:
		/* Target is a process, not a file - can't cache */
		return (false);
	default:
		break;
	}

	if (oes_cache_file_valid(&file)) {
		key->eck_flags |= OES_CACHE_KEY_FILE;
		key->eck_file = file;
	}
	if (oes_cache_file_valid(&target)) {
		key->eck_flags |= OES_CACHE_KEY_TARGET;
		key->eck_target = target;
	}
	if ((key->eck_flags & OES_CACHE_KEY_FILE) == 0)
		return (false);
	if (oes_cache_event_requires_target(msg->em_event) &&
	    (key->eck_flags & OES_CACHE_KEY_TARGET) == 0)
		return (false);

	return (true);
}

static void
oes_cache_remove_entry_locked(struct oes_client *ec,
    struct oes_cache_entry *entry, bool expired, bool eviction)
{
	EC_LOCK_ASSERT(ec);
	LIST_REMOVE(entry, ece_link);
	TAILQ_REMOVE(&ec->ec_cache_lru, entry, ece_lru);
	if (ec->ec_cache_entries > 0)
		ec->ec_cache_entries--;
	if (expired)
		ec->ec_cache_expired++;
	else if (eviction)
		ec->ec_cache_evictions++;
	free(entry, M_OES);
}

static void
oes_cache_clear_locked(struct oes_client *ec)
{
	struct oes_cache_entry *entry, *tmp;

	EC_LOCK_ASSERT(ec);
	TAILQ_FOREACH_SAFE(entry, &ec->ec_cache_lru, ece_lru, tmp)
		oes_cache_remove_entry_locked(ec, entry, false, false);
}

static bool
oes_cache_flags_valid(uint32_t flags)
{
	/* Require at least PROCESS key to prevent overly broad cache entries */
	if ((flags & OES_CACHE_KEY_PROCESS) == 0)
		return (false);
	return ((flags & ~(OES_CACHE_KEY_PROCESS | OES_CACHE_KEY_FILE |
	    OES_CACHE_KEY_TARGET)) == 0);
}

void
oes_cache_init(struct oes_client *ec)
{
	int i;

	for (i = 0; i < OES_CACHE_BUCKETS; i++)
		LIST_INIT(&ec->ec_cache[i]);
	TAILQ_INIT(&ec->ec_cache_lru);
	ec->ec_cache_entries = 0;
	ec->ec_cache_max = oes_cache_max_entries;
}

void
oes_cache_destroy(struct oes_client *ec)
{
	EC_LOCK_ASSERT(ec);
	oes_cache_clear_locked(ec);
}

int
oes_client_cache_add(struct oes_client *ec, const oes_cache_entry_t *entry)
{
	struct oes_cache_entry *cur;
	struct oes_cache_entry *victim;
	struct oes_cache_entry *new_entry;
	struct timespec expires;
	uint32_t idx;

	if (entry == NULL)
		return (EINVAL);
	if (entry->ece_key.eck_event == OES_CACHE_EVENT_ANY)
		return (EINVAL);
	if (!oes_event_is_valid(entry->ece_key.eck_event) ||
	    !OES_EVENT_IS_AUTH(entry->ece_key.eck_event))
		return (EINVAL);
	if (entry->ece_key.eck_pad != 0)
		return (EINVAL);
	/* AUTH_PTRACE targets processes, not files - can't cache */
	if (entry->ece_key.eck_event == OES_EVENT_AUTH_PTRACE)
		return (EINVAL);
	if (!oes_cache_flags_valid(entry->ece_key.eck_flags))
		return (EINVAL);
	if (!oes_cache_proc_valid(&entry->ece_key.eck_process))
		return (EINVAL);
	if ((entry->ece_key.eck_flags & OES_CACHE_KEY_FILE) == 0 ||
	    !oes_cache_file_valid(&entry->ece_key.eck_file))
		return (EINVAL);
	if (oes_cache_event_requires_target(entry->ece_key.eck_event) &&
	    ((entry->ece_key.eck_flags & OES_CACHE_KEY_TARGET) == 0 ||
	    !oes_cache_file_valid(&entry->ece_key.eck_target)))
		return (EINVAL);
	if (entry->ece_result != OES_AUTH_ALLOW &&
	    entry->ece_result != OES_AUTH_DENY)
		return (EINVAL);
	if (entry->ece_ttl_ms == 0 ||
	    entry->ece_ttl_ms > OES_MAX_CACHE_TTL_MS)
		return (EINVAL);

	oes_cache_make_deadline(&expires, entry->ece_ttl_ms);
	new_entry = malloc(sizeof(*new_entry), M_OES, M_WAITOK | M_ZERO);
	new_entry->ece_key = entry->ece_key;
	new_entry->ece_result = entry->ece_result;
	new_entry->ece_expires = expires;

	EC_LOCK(ec);
	if (ec->ec_cache_max == 0) {
		EC_UNLOCK(ec);
		free(new_entry, M_OES);
		return (ENOSPC);
	}

	idx = oes_cache_bucket(entry->ece_key.eck_event);
	LIST_FOREACH(cur, &ec->ec_cache[idx], ece_link) {
		if (oes_cache_key_equal(&cur->ece_key, &entry->ece_key)) {
			cur->ece_result = entry->ece_result;
			cur->ece_expires = expires;
			TAILQ_REMOVE(&ec->ec_cache_lru, cur, ece_lru);
			TAILQ_INSERT_HEAD(&ec->ec_cache_lru, cur, ece_lru);
			EC_UNLOCK(ec);
			free(new_entry, M_OES);
			return (0);
		}
	}

	LIST_INSERT_HEAD(&ec->ec_cache[idx], new_entry, ece_link);
	TAILQ_INSERT_HEAD(&ec->ec_cache_lru, new_entry, ece_lru);
	ec->ec_cache_entries++;

	while (ec->ec_cache_entries > ec->ec_cache_max) {
		victim = TAILQ_LAST(&ec->ec_cache_lru, oes_cache_lru);
		if (victim == NULL)
			break;
		oes_cache_remove_entry_locked(ec, victim, false, true);
	}

	EC_UNLOCK(ec);
	return (0);
}

int
oes_client_cache_remove(struct oes_client *ec, const oes_cache_key_t *key)
{
	struct oes_cache_entry *cur, *tmp;
	uint32_t idx;
	uint32_t removed = 0;
	uint32_t flags;

	if (key == NULL)
		return (EINVAL);
	if (key->eck_event != OES_CACHE_EVENT_ANY &&
	    (!oes_event_is_valid(key->eck_event) ||
	     !OES_EVENT_IS_AUTH(key->eck_event)))
		return (EINVAL);
	if (key->eck_pad != 0)
		return (EINVAL);
	flags = key->eck_flags;
	if (!oes_cache_flags_valid(flags))
		return (EINVAL);

	EC_LOCK(ec);
	if (key->eck_event == OES_CACHE_EVENT_ANY) {
		for (idx = 0; idx < OES_CACHE_BUCKETS; idx++) {
			LIST_FOREACH_SAFE(cur, &ec->ec_cache[idx], ece_link,
			    tmp) {
				if (!oes_cache_key_match_remove(&cur->ece_key,
				    key))
					continue;
				oes_cache_remove_entry_locked(ec, cur, false,
				    false);
				removed++;
			}
		}
	} else {
		idx = oes_cache_bucket(key->eck_event);
		LIST_FOREACH_SAFE(cur, &ec->ec_cache[idx], ece_link, tmp) {
			if (!oes_cache_key_match_remove(&cur->ece_key, key))
				continue;
			oes_cache_remove_entry_locked(ec, cur, false, false);
			removed++;
		}
	}
	EC_UNLOCK(ec);

	return (removed > 0 ? 0 : ESRCH);
}

void
oes_client_cache_clear(struct oes_client *ec)
{
	EC_LOCK(ec);
	oes_cache_clear_locked(ec);
	EC_UNLOCK(ec);
}

bool
oes_client_cache_lookup(struct oes_client *ec, const struct oes_pending *ep,
    oes_auth_result_t *result)
{
	struct oes_cache_entry *cur, *tmp;
	oes_cache_key_t lookup;
	struct timespec now;
	uint32_t idx;

	EC_LOCK_ASSERT(ec);

	if (ec->ec_cache_max == 0 || ec->ec_cache_entries == 0)
		return (false);
	if (!oes_cache_key_from_pending(ep, &lookup))
		return (false);

	nanouptime(&now);
	idx = oes_cache_bucket(lookup.eck_event);

	LIST_FOREACH_SAFE(cur, &ec->ec_cache[idx], ece_link, tmp) {
		if (timespeccmp(&now, &cur->ece_expires, >=)) {
			oes_cache_remove_entry_locked(ec, cur, true, false);
			continue;
		}
		if (!oes_cache_key_equal(&cur->ece_key, &lookup))
			continue;
		TAILQ_REMOVE(&ec->ec_cache_lru, cur, ece_lru);
		TAILQ_INSERT_HEAD(&ec->ec_cache_lru, cur, ece_lru);
		ec->ec_cache_hits++;
		SDT_PROBE3(oes, , , cache__hit,
		    ep->ep_msg.em_event,
		    ep->ep_msg.em_process.ep_pid,
		    cur->ece_result);
		if (result != NULL)
			*result = cur->ece_result;
		return (true);
	}

	ec->ec_cache_misses++;
	SDT_PROBE2(oes, , , cache__miss,
	    ep->ep_msg.em_event,
	    ep->ep_msg.em_process.ep_pid);
	return (false);
}
