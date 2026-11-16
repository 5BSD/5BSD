# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard

/([0-9])+ T xread/ {
    x = $1 - ORG1;
    printf("#define XREADORG %#x\n", REL1 + x)
}
