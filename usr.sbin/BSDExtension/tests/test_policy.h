/* SPDX-License-Identifier: BSD-2-Clause */
/* Explicit test input, independent of the installed deployment policy. */
static void
test_base_policy(struct sysext_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	strlcpy(cfg->allow[0], "cryptodev", SYSEXT_NAME_MAX);
	strlcpy(cfg->allow[1], "zfs", SYSEXT_NAME_MAX);
	strlcpy(cfg->allow[2], "vhid", SYSEXT_NAME_MAX);
	cfg->nallow = 3;
}
