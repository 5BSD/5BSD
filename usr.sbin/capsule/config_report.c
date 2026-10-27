/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucl.h>
#include "config.h"

/* Report target paths, not the validation host's enforcement state. */
static unsigned char *
validation_string(const char *value)
{
	ucl_object_t *object;
	unsigned char *encoded;

	object = ucl_object_fromstring(value);
	if (object == NULL)
		err(1, "validation report");
	encoded = ucl_object_emit(object, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(object);
	if (encoded == NULL)
		err(1, "validation report encoding");
	return (encoded);
}

void
config_validation_report(const struct capsule_config *cfg)
{
	unsigned char *manager, *boot_path, *normal_path;

	manager = validation_string(cfg->service_manager);
	boot_path = validation_string(CAPSULE_DEFAULT_CONFFILE);
	normal_path = validation_string(CAPSULE_DEFAULT_CONFFILE);
	printf("{\"format\":2,\"scope\":\"capsule-effective-manager\","
	    "\"service_manager\":%s,\"boot_configuration\":%s,"
	    "\"normal_boot_configuration\":%s}\n", manager, boot_path, normal_path);
	free(normal_path);
	free(boot_path);
	free(manager);
	if (fflush(stdout) == EOF)
		err(1, "validation report");
}
