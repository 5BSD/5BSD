/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <string.h>

#include "pci_fbuf_model.h"

ATF_TC_WITHOUT_HEAD(register_access_bounds);
ATF_TC_BODY(register_access_bounds, tc)
{
	uint8_t registers[PCI_FBUF_REG_SIZE];
	uint64_t value;

	memset(registers, 0, sizeof(registers));
	ATF_CHECK(pci_fbuf_register_write(registers, 127, 1, 0xa5));
	ATF_CHECK(pci_fbuf_register_read(registers, 127, 1, &value));
	ATF_CHECK_EQ(UINT64_C(0xa5), value);
	ATF_CHECK(!pci_fbuf_register_write(registers, 127, 2, 0));
	ATF_CHECK(!pci_fbuf_register_read(registers, UINT64_MAX, 1, &value));
	ATF_CHECK(!pci_fbuf_register_write(registers, 0, 3, 0));
}

ATF_TC_WITHOUT_HEAD(register_little_endian_unaligned);
ATF_TC_BODY(register_little_endian_unaligned, tc)
{
	uint8_t registers[PCI_FBUF_REG_SIZE];
	uint64_t value;

	memset(registers, 0, sizeof(registers));
	ATF_REQUIRE(pci_fbuf_register_write(registers, 1, 4,
	    UINT32_C(0x78563412)));
	ATF_CHECK_EQ(0x12, registers[1]);
	ATF_CHECK_EQ(0x34, registers[2]);
	ATF_CHECK_EQ(0x56, registers[3]);
	ATF_CHECK_EQ(0x78, registers[4]);
	ATF_REQUIRE(pci_fbuf_register_read(registers, 1, 4, &value));
	ATF_CHECK_EQ(UINT64_C(0x78563412), value);
}

ATF_TC_WITHOUT_HEAD(register_geometry_layout);
ATF_TC_BODY(register_geometry_layout, tc)
{
	uint8_t registers[PCI_FBUF_REG_SIZE];
	uint64_t value;

	memset(registers, 0, sizeof(registers));
	ATF_REQUIRE(pci_fbuf_register_write(registers, PCI_FBUF_REG_FBSIZE, 4,
	    UINT32_C(32 * 1024 * 1024)));
	ATF_REQUIRE(pci_fbuf_register_write(registers, PCI_FBUF_REG_WIDTH, 2,
	    1024));
	ATF_REQUIRE(pci_fbuf_register_write(registers, PCI_FBUF_REG_HEIGHT, 2,
	    768));
	ATF_REQUIRE(pci_fbuf_register_write(registers, PCI_FBUF_REG_DEPTH, 2,
	    32));
	ATF_REQUIRE(pci_fbuf_register_read(registers, PCI_FBUF_REG_WIDTH, 2,
	    &value));
	ATF_CHECK_EQ(1024, value);
	ATF_REQUIRE(pci_fbuf_register_read(registers, PCI_FBUF_REG_HEIGHT, 2,
	    &value));
	ATF_CHECK_EQ(768, value);
	ATF_REQUIRE(pci_fbuf_register_read(registers, PCI_FBUF_REG_DEPTH, 2,
	    &value));
	ATF_CHECK_EQ(32, value);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, register_access_bounds);
	ATF_TP_ADD_TC(tp, register_little_endian_unaligned);
	ATF_TP_ADD_TC(tp, register_geometry_layout);
	return (atf_no_error());
}
