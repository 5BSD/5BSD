/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

static const char component_notes[]
    __attribute__((section(".note.5bsd.components"), used)) =
    "interface=org.5bsd.cmp.network\n"
    "version=1.0.0\n"
    "local-name=network\n"
    "required=true\n"
    "interface=org.5bsd.cmp.filesystem\n"
    "version=1.0.0\n"
    "local-name=filesystem\n"
    "required=true\n";

int
main(void)
{

	return (component_notes[0] == '\0');
}
