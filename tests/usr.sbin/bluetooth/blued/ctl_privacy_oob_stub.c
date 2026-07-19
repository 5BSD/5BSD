/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Test-only providers for ctl.c's runtime privacy and SC-OOB seams.
 */

#include <sys/cdefs.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "blued_devmgr.h"
#include "hci_util.h"
#include "smp.h"

extern uint8_t blued_local_irk[16];
extern bool blued_has_local_irk;
extern struct blued_reslist blued_reslist;

uint8_t blued_local_irk[16];
bool blued_has_local_irk;
struct blued_reslist blued_reslist;

void
hci_l2cap_set_own_address_type(uint8_t own_addr_type __unused)
{
}

int
blued_reslist_add(struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (rl == NULL || addr == NULL)
		return (0);
	if (blued_reslist_contains(rl, addr, addr_type))
		return (0);
	if (rl->count >= BLUED_RESLIST_MAX)
		return (0);
	i = rl->count++;
	memcpy(rl->ent[i].addr, addr, 6);
	rl->ent[i].addr_type = addr_type;
	return (1);
}

int
blued_reslist_remove(struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (rl == NULL || addr == NULL)
		return (0);
	for (i = 0; i < rl->count; i++) {
		if (rl->ent[i].addr_type == addr_type &&
		    memcmp(rl->ent[i].addr, addr, 6) == 0) {
			if (i != rl->count - 1)
				rl->ent[i] = rl->ent[rl->count - 1];
			rl->count--;
			return (1);
		}
	}
	return (0);
}

bool
blued_reslist_contains(const struct blued_reslist *rl, const uint8_t addr[6],
    uint8_t addr_type)
{
	int i;

	if (rl == NULL || addr == NULL)
		return (false);
	for (i = 0; i < rl->count; i++) {
		if (rl->ent[i].addr_type == addr_type &&
		    memcmp(rl->ent[i].addr, addr, 6) == 0)
			return (true);
	}
	return (false);
}

int
hci_le_set_addr_resolution_enable(int hci_fd __unused, uint8_t enable __unused)
{

	return (0);
}

int
hci_le_clear_resolving_list(int hci_fd __unused)
{

	memset(&blued_reslist, 0, sizeof(blued_reslist));
	return (0);
}

int
hci_le_add_dev_resolving_list(int hci_fd __unused, uint8_t addr_type __unused,
    const uint8_t addr[6] __unused, const uint8_t peer_irk[16] __unused,
    const uint8_t local_irk[16] __unused)
{

	return (0);
}

int
hci_le_remove_dev_resolving_list(int hci_fd __unused,
    uint8_t addr_type __unused, const uint8_t addr[6] __unused)
{

	return (0);
}

int
hci_le_set_privacy_mode(int hci_fd __unused, uint8_t addr_type __unused,
    const uint8_t addr[6] __unused, uint8_t mode __unused)
{

	return (0);
}

int
smp_sc_oob_generate_local(uint8_t confirm[16], uint8_t random[16],
    uint8_t pkx_le[32])
{

	memset(confirm, 0x11, 16);
	memset(random, 0x22, 16);
	memset(pkx_le, 0x33, 32);
	return (0);
}

void
smp_sc_oob_clear_local(void)
{
}
