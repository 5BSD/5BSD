/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd — decode kernel name-set nvlists.
 *
 * The zfshandle list verbs pack their results with the OpenZFS nvpair
 * encoder, not nv(9).  This translation unit is the only libnvpair
 * consumer so the OpenZFS headers stay out of the rest of the daemon.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
 * Minimal libnvpair surface.  The full <libnvpair.h> needs the OpenZFS
 * libspl include environment, which conflicts with the daemon's kernel
 * -I${SRCTOP}/sys include path.  These prototypes and the boolean type
 * tag match the stable OpenZFS nvpair ABI that libnvpair.so exports.
 */
typedef struct nvlist nvlist_t;
typedef struct nvpair nvpair_t;
#define	NVWALK_DATA_TYPE_BOOLEAN	1

int	nvlist_unpack(char *, size_t, nvlist_t **, int);
void	nvlist_free(nvlist_t *);
nvpair_t *nvlist_next_nvpair(nvlist_t *, nvpair_t *);
char	*nvpair_name(nvpair_t *);
int	nvpair_type(nvpair_t *);

int	tzfsd_nvl_names(const void *buf, size_t len, char ***namesp,
	    size_t *countp);
void	tzfsd_nvl_names_free(char **names, size_t count);

/*
 * Unpack a boolean name-set nvlist into a NULL-free string array.
 * An empty set yields count 0 with a non-NULL array.  Returns 0 on
 * success, -1 with errno set otherwise.
 */
int
tzfsd_nvl_names(const void *buf, size_t len, char ***namesp, size_t *countp)
{
	nvlist_t *nvl;
	nvpair_t *elem;
	char **names;
	size_t count, i;

	*namesp = NULL;
	*countp = 0;
	nvl = NULL;
	if (nvlist_unpack((char *)(uintptr_t)buf, len, &nvl, 0) != 0) {
		errno = EPROTO;
		return (-1);
	}
	count = 0;
	for (elem = nvlist_next_nvpair(nvl, NULL); elem != NULL;
	    elem = nvlist_next_nvpair(nvl, elem)) {
		if (nvpair_type(elem) != NVWALK_DATA_TYPE_BOOLEAN) {
			nvlist_free(nvl);
			errno = EPROTO;
			return (-1);
		}
		count++;
	}
	names = calloc(count == 0 ? 1 : count, sizeof(*names));
	if (names == NULL) {
		nvlist_free(nvl);
		return (-1);
	}
	i = 0;
	for (elem = nvlist_next_nvpair(nvl, NULL); elem != NULL;
	    elem = nvlist_next_nvpair(nvl, elem)) {
		names[i] = strdup(nvpair_name(elem));
		if (names[i] == NULL) {
			tzfsd_nvl_names_free(names, i);
			nvlist_free(nvl);
			return (-1);
		}
		i++;
	}
	nvlist_free(nvl);
	*namesp = names;
	*countp = count;
	return (0);
}

void
tzfsd_nvl_names_free(char **names, size_t count)
{
	size_t i;

	if (names == NULL)
		return;
	for (i = 0; i < count; i++)
		free(names[i]);
	free(names);
}
