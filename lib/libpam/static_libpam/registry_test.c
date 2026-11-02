/* SPDX-License-Identifier: BSD-2-Clause */
/* Inspect registration only. Never invoke PAM handlers or load a module. */
#include <sys/types.h>
#include <sys/linker_set.h>
#include <stdio.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/openpam.h>

pam_module_t *openpam_static(const char *);
SET_DECLARE(_openpam_static_modules, pam_module_t);

int
main(int argc, char **argv)
{
	pam_module_t **entry;
	char expected[128];
	size_t count = 0;
	int functions;

	if (argc < 2)
		return (2);
	SET_FOREACH(entry, _openpam_static_modules) {
		if (count >= (size_t)(argc - 1))
			return (3);
		if (snprintf(expected, sizeof(expected), "%s.so", argv[count + 1]) >=
		    (int)sizeof(expected))
			return (4);
		if (*entry == NULL || (*entry)->path == NULL ||
		    strcmp((*entry)->path, expected) != 0 ||
		    openpam_static(expected) != *entry || (*entry)->dlh != NULL)
			return (5);
		functions = 0;
		for (int i = 0; i < PAM_NUM_PRIMITIVES; ++i)
			functions += (*entry)->func[i] != NULL;
		if (functions == 0)
			return (6);
		printf("%zu %s %d handlers\n", count, expected, functions);
		++count;
	}
	if (count != (size_t)(argc - 1) ||
	    openpam_static("__unselected_static_registry_test__.so") != NULL)
		return (7);
	return (0);
}
