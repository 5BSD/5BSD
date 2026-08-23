/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Shim so a TU-include harness can satisfy pci_xhci.c's <xhcireg.h> when the
 * kernel controller include directory is not on the default search path.
 */
#include <dev/usb/controller/xhcireg.h>
