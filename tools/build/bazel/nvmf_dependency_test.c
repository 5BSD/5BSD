/* SPDX-License-Identifier: BSD-2-Clause */
/* Qualify a static consumer of libnvmf and its transitive libnv dependency. */
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libnvmf.h"
#include "internal.h"

int
main(void)
{
	nvlist_t *input, *decoded;
	struct nvmf_ioc_nv packed;
	int error;

	input = nvlist_create(0);
	if (input == NULL)
		return (1);
	nvlist_add_string(input, "transport", "tcp");
	nvlist_add_number(input, "queue-size", 128);
	error = nvmf_pack_ioc_nvlist(&packed, input);
	if (error != 0 || packed.data == NULL || packed.size == 0)
		return (2);
	decoded = nvlist_unpack(packed.data, packed.size, 0);
	if (decoded == NULL || !nvlist_exists_string(decoded, "transport") ||
	    !nvlist_exists_number(decoded, "queue-size") ||
	    strcmp(nvlist_get_string(decoded, "transport"), "tcp") != 0 ||
	    nvlist_get_number(decoded, "queue-size") != 128)
		return (3);
	free(packed.data);
	nvlist_destroy(decoded);
	nvlist_set_error(input, EINVAL);
	if (nvmf_pack_ioc_nvlist(&packed, input) != EINVAL ||
	    packed.data != NULL || packed.size != 0)
		return (4);
	nvlist_destroy(input);
	if (strcmp(nvmf_transport_type(NVMF_TRTYPE_TCP), "TCP") != 0)
		return (5);
	puts("libnvmf transitive libnv serialization and error handling passed");
	return (0);
}
