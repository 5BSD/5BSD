/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Experimental cleanup consumer. Installation transactions do not call this.
 */
#include <errno.h>
#include <string.h>
#include "switchboard_reclamation.h"
#include "switchboard_lifecycle_private.h"

int
sl_register_provider(struct sl_db *db, const char *label)
{
	struct sl_record *r;

	if (!sl_label_valid(label))
		return (errno = EINVAL, -1);
	for (size_t i = 0; i < db->count; i++)
		if (db->records[i].kind == SL_PROVIDER &&
		    strcmp(db->records[i].label, label) == 0)
			return (0);
	r = sl_append(db);
	if (r == NULL)
		return (-1);
	r->kind = SL_PROVIDER;
	strlcpy(r->label, label, sizeof(r->label));
	return (0);
}

int
sl_cleanup_prepare(struct sl_db *db, const char *label, const uint8_t *generation)
{
	struct sl_record *r, *p;
	size_t n;
	bool legacy;
	char label_copy[SL_LABEL_MAX];
	uint8_t generation_copy[SL_GENERATION_SIZE];

	if (!sl_label_valid(label) || generation == NULL || !sl_generation_valid(generation))
		return (errno = EINVAL, -1);
	strlcpy(label_copy, label, sizeof(label_copy));
	memcpy(generation_copy, generation, sizeof(generation_copy));
	label = label_copy;
	generation = generation_copy;

	r = sl_generation(db, label, generation);
	if (r == NULL)
		return (errno = ESTALE, -1);
	if (r->phase == SL_RETIRED)
		return (0);
	if (r->phase != SL_COMPLETE)
		return (errno = EBUSY, -1);
	/* A completed delivery batch must not grow when more providers register. */
	for (size_t i = 0; i < db->count; i++)
		if (db->records[i].kind == SL_DELIVERY &&
		    strcmp(db->records[i].label, label) == 0 &&
		    memcmp(db->records[i].generation, generation, SL_GENERATION_SIZE) == 0)
			return (0);
	legacy = strcmp(r->provider, r->label) == 0;
	n = db->count;
	for (size_t i = 0; i < n; i++) {
		char provider[SL_LABEL_MAX];
		struct sl_record *held = &db->records[i];
		if (legacy) {
			if (held->kind != SL_PROVIDER)
				continue;
			strlcpy(provider, held->label, sizeof(provider));
		} else {
			if (held->kind != SL_HOLDING || strcmp(held->label, label) != 0 ||
			    memcmp(held->generation, generation, SL_GENERATION_SIZE) != 0)
				continue;
			strlcpy(provider, held->provider, sizeof(provider));
		}
		p = sl_append(db);
		if (p == NULL)
			return (-1);
		p->kind = SL_DELIVERY;
		strlcpy(p->label, label, sizeof(p->label));
		strlcpy(p->provider, provider, sizeof(p->provider));
		memcpy(p->generation, generation, SL_GENERATION_SIZE);
	}
	r = sl_generation(db, label, generation);
	r->phase = SL_RETIRED;
	db->dirty = true;
	return (0);
}

int
sl_ack(struct sl_db *db, const char *label, const char *provider,
    const uint8_t *generation)
{
	struct sl_record *r = sl_generation(db, label, generation);
	bool found = false, pending = false;

	if (r == NULL || memcmp(r->generation, generation, SL_GENERATION_SIZE) != 0)
		return (errno = ESTALE, -1);
	if (r->phase != SL_RETIRED && r->phase != SL_COMPLETE)
		return (errno = EBUSY, -1);
	for (size_t i = 0; i < db->count; i++) {
		struct sl_record *p = &db->records[i];
		if (p->kind != SL_DELIVERY || strcmp(p->label, label) != 0 ||
		    memcmp(p->generation, generation, SL_GENERATION_SIZE) != 0)
			continue;
		if (strcmp(p->provider, provider) == 0) {
			if (p->phase == 0) {
				p->phase = 1;
				db->dirty = true;
			}
			found = true;
		}
		if (p->phase == 0)
			pending = true;
	}
	if (!found)
		return (errno = EPERM, -1);
	if (!pending)
		r->phase = SL_COMPLETE;
	return (0);
}

int
sl_track_holding(struct sl_db *db, const char *label, const char *provider,
    const uint8_t *generation)
{
	struct sl_record *r;
	char label_copy[SL_LABEL_MAX], provider_copy[SL_LABEL_MAX];
	uint8_t generation_copy[SL_GENERATION_SIZE];

	if (!sl_label_valid(label) || !sl_label_valid(provider))
		return (errno = EINVAL, -1);
	r = sl_generation(db, label, generation);
	if (r == NULL || r->phase != SL_ACTIVE)
		return (errno = ESTALE, -1);
	for (size_t i = 0; i < db->count; i++) {
		r = &db->records[i];
		if (r->kind == SL_HOLDING && strcmp(r->label, label) == 0 &&
		    strcmp(r->provider, provider) == 0 &&
		    memcmp(r->generation, generation, SL_GENERATION_SIZE) == 0)
			return (0);
	}
	strlcpy(label_copy, label, sizeof(label_copy));
	strlcpy(provider_copy, provider, sizeof(provider_copy));
	memcpy(generation_copy, generation, sizeof(generation_copy));
	label = label_copy;
	provider = provider_copy;
	generation = generation_copy;
	r = sl_append(db);
	if (r == NULL)
		return (-1);
	r->kind = SL_HOLDING;
	strlcpy(r->label, label, sizeof(r->label));
	strlcpy(r->provider, provider, sizeof(r->provider));
	memcpy(r->generation, generation, SL_GENERATION_SIZE);
	return (0);
}
