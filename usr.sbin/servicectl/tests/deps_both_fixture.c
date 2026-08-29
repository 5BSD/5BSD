/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

static const char component_notes[]
    __attribute__((section(".note.5bsd.descriptors"), used)) =
    "interface=system.Network\n"
    "version=1.0.0\n"
    "local-name=network\n"
    "required=true\n"
    "interface=system.Filesystem\n"
    "version=1.0.0\n"
    "local-name=filesystem\n"
    "required=true\n"
    "interface=system.Crypto\n"
    "version=1.0.0\n"
    "local-name=crypto\n"
    "required=true\n"
    "interface=system.Log\n"
    "version=1.0.0\n"
    "local-name=logging\n"
    "required=true\n"
    "interface=system.Trace\n"
    "version=1.0.0\n"
    "local-name=tracing\n"
    "required=true\n"
    "interface=system.Notify\n"
    "version=1.0.0\n"
    "local-name=notifications\n"
    "required=true\n";

int
main(void)
{

	return (component_notes[0] == '\0');
}
