/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <libservice.h>
#include "bsdextension.h"

/*
 * Workers share two slots.  Publication changes active only after the inactive
 * slot is complete.  If a worker dies holding the robust mutex, the active
 * slot is still a complete policy and the next worker can recover it.
 */
struct sysext_policy {
	pthread_mutex_t lock;
	unsigned active;
	struct sysext_config slots[2];
};

static int
policy_lock(struct sysext_policy *policy)
    __trylocks_exclusive(0, &policy->lock) __no_lock_analysis
{
	int error;

	error = pthread_mutex_lock(&policy->lock);
	if (error == EOWNERDEAD) {
		error = pthread_mutex_consistent(&policy->lock);
		if (error != 0)
			(void)pthread_mutex_unlock(&policy->lock);
	}
	if (error != 0) {
		errno = error;
		return (-1);
	}
	return (0);
}

struct sysext_policy *
sysext_policy_create(const struct sysext_config *initial)
{
	struct sysext_policy *policy;
	pthread_mutexattr_t attr;
	int error;

	policy = mmap(NULL, sizeof(*policy), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	if (policy == MAP_FAILED)
		return (NULL);
	memset(policy, 0, sizeof(*policy));
	error = pthread_mutexattr_init(&attr);
	if (error != 0)
		goto fail;
	error = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	if (error == 0)
		error = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
	if (error == 0)
		error = pthread_mutex_init(&policy->lock, &attr);
	(void)pthread_mutexattr_destroy(&attr);
	if (error != 0)
		goto fail;
	policy->slots[0] = *initial;
	return (policy);
fail:
	munmap(policy, sizeof(*policy));
	errno = error;
	return (NULL);
}

void
sysext_policy_destroy(struct sysext_policy *policy)
{
	(void)pthread_mutex_destroy(&policy->lock);
	(void)munmap(policy, sizeof(*policy));
}

int
sysext_policy_snapshot(struct sysext_policy *policy, struct sysext_config *out)
{
	if (policy_lock(policy) != 0)
		return (-1);
	*out = policy->slots[policy->active];
	(void)pthread_mutex_unlock(&policy->lock);
	return (0);
}

int
sysext_policy_reload(struct sysext_policy *policy, const char *path,
    service_rights_t rights)
{
	struct sysext_config candidate;
	unsigned next;
	int error;

	if (!service_rights_allow(rights, SERVICE_RIGHTS_ADMIN)) {
		errno = EPERM;
		return (-1);
	}
	/* Serialize reloads so an older read cannot overwrite a newer reload. */
	if (policy_lock(policy) != 0)
		return (-1);
	memset(&candidate, 0, sizeof(candidate));
	if (sysext_config_reload(&candidate, path) == -1) {
		error = errno;
		(void)pthread_mutex_unlock(&policy->lock);
		errno = error;
		return (-1);
	}
	next = policy->active ^ 1;
	policy->slots[next] = candidate;
	/* The mutex orders readers; release fences also order owner-death recovery. */
	__atomic_store_n(&policy->active, next, __ATOMIC_RELEASE);
	(void)pthread_mutex_unlock(&policy->lock);
	return (0);
}

#ifdef BSDEXTENSION_TESTING
void
sysext_test_policy_abandon(struct sysext_policy *policy)
    __no_lock_analysis
{
	(void)policy_lock(policy);
	/* Leave the inactive slot corrupt, as if reload died before publication. */
	memset(&policy->slots[policy->active ^ 1], 0xff,
	    sizeof(policy->slots[0]));
}
#endif
