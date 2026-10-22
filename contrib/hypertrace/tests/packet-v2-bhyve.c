/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/mbufid.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "packet-v2-bhyve.inc"

int
main(void)
{
	mbufid_v2_t id = {};

	assert(pci_vtnet_packet_id_valid(&id, false, false));
	assert(pci_vtnet_packet_id_valid(&id, true, false));
	id.mv2_id.mid_hostid = 12;
	id.mv2_id.mid_msgid = 99;
	id.mv2_id.mid_magic = MBUFID_MAGIC_NUMBER;
	assert(pci_vtnet_packet_id_valid(&id, false, true));
	assert(!pci_vtnet_packet_id_valid(&id, true, false));
	assert(pci_vtnet_packet_id_valid(&id, true, true));
	id.mv2_epoch = 7;
	id.mv2_stamp = 9;
	assert(pci_vtnet_packet_id_valid(&id, true, false));
	assert(pci_vtnet_packet_id_valid(&id, true, true));
	id.mv2_stamp = 0;
	assert(!pci_vtnet_packet_id_valid(&id, true, false));
	assert(!pci_vtnet_packet_id_valid(&id, true, true));
	id.mv2_stamp = 9;
	id.mv2_id.__mid_pad[0] = 1;
	assert(!pci_vtnet_packet_id_valid(&id, true, false));
	assert(!pci_vtnet_packet_id_valid(&id, false, true));
	puts("PASS: bhyve V2 RX rejects fresh and malformed records; TX permits fresh");
	return (0);
}
