/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINUXKPI_LINUX_CLK_H_
#define _LINUXKPI_LINUX_CLK_H_
#include <linux/device.h>
#include <linux/err.h>
#define clk linux_clk
struct clk;
struct clk *linux_devm_clk_get_optional_enabled_with_rate(struct device *,
    const char *, unsigned long);
#define devm_clk_get_optional_enabled_with_rate linux_devm_clk_get_optional_enabled_with_rate
#endif
