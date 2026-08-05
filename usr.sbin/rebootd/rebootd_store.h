/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _REBOOTD_STORE_H_
#define	_REBOOTD_STORE_H_

struct rebootd_state_record;
struct rebootd_store;

enum rebootd_store_commit {
	REBOOTD_STORE_NOT_COMMITTED = 0,
	REBOOTD_STORE_VISIBLE,
	REBOOTD_STORE_DURABLE
};

int	rebootd_store_open(struct rebootd_store **);
int	rebootd_store_load(struct rebootd_store *,
	    struct rebootd_state_record *);
int	rebootd_store_save(struct rebootd_store *,
	    const struct rebootd_state_record *, enum rebootd_store_commit *);
void	rebootd_store_close(struct rebootd_store *);

#endif
