/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

static const char component_notes[]
    __attribute__((section(".note.5bsd.components"), used)) =
    "interface=org.5bsd.network\n"
    "version=1.0.0\n"
    "local-name=network\n"
    "required=true\n"
    "interface=org.5bsd.filesystem\n"
    "version=1.0.0\n"
    "local-name=filesystem\n"
    "required=true\n"
    "interface=org.5bsd.log\n"
    "version=1.0.0\n"
    "local-name=logging\n"
    "required=true\n"
    "interface=org.5bsd.trace\n"
    "version=1.0.0\n"
    "local-name=tracing\n"
    "required=true\n"
    "interface=org.5bsd.notify\n"
    "version=1.0.0\n"
    "local-name=notifications\n"
    "required=true\n";

int
main(void)
{

	return (component_notes[0] == '\0');
}
