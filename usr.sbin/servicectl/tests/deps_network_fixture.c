/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

static const char network_note[]
    __attribute__((section(".note.5bsd.descriptors"), used)) =
    "interface=system.Network\n"
    "version=1.0.0\n"
    "local-name=network\n"
    "required=true\n";

int
main(void)
{

	return (network_note[0] == '\0');
}
