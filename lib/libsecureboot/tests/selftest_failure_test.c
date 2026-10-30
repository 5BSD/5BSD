/* SPDX-License-Identifier: BSD-2-Clause */
/* Include the production implementation to reach its private KAT expectations.
 * The other components and cryptographic implementations are linked normally. */
#include "../vets.c"

int
main(int argc, char **argv)
{
	char *expected = NULL, saved = 0;
	int result;

	if (argc != 2)
		return 1;
	if (strcmp(argv[1], "bad256") == 0)
		expected = vh_SHA256;
	else if (strcmp(argv[1], "bad384") == 0)
		expected = vh_SHA384;
	else if (strcmp(argv[1], "clean") != 0)
		return 2;
	if (ve_trust_init() != 1)
		return 3;
	/* The historic upstream fixture exercises signatures independently of time. */
	ve_enforce_validity_set(0);
	if (expected != NULL) {
		saved = expected[0];
		expected[0] = saved == '0' ? '1' : '0';
	}
	result = ve_self_tests();
	if (expected == NULL)
		return result == 1 && ve_self_tests() == 1 ? 0 : 4;
	if (result != 0)
		return 5;
	expected[0] = saved;
	/* Failure must remain cached even after the test repairs the expected hash. */
	return ve_self_tests() == 0 ? 0 : 6;
}
