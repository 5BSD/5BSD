/* SPDX-License-Identifier: BSD-2-Clause */
#include "opt_platform.h"
#include <sys/param.h>
#include <sys/bus.h>
#ifdef FDT
#include <dev/clk/clk.h>
#endif
#include <linux/clk.h>
#include <linux/of.h>
#include <linux/slab.h>

#ifdef FDT
struct linux_clk {
	clk_t native;
};

static void
lkpi_clk_release(void *arg)
{
	struct linux_clk *clk = arg;

	clk_disable(clk->native);
	clk_release(clk->native);
	kfree(clk);
}
#endif

struct linux_clk *
linux_devm_clk_get_optional_enabled_with_rate(struct device *dev,
    const char *name, unsigned long rate)
{
#ifdef FDT
	struct linux_clk *clk;
	const char *entry;
	uint64_t frequency;
	int error, count, i;

	if (dev->of_node == NULL ||
	    !of_property_read_bool(dev->of_node, "clocks"))
		return (NULL);
	/* A NULL ID selects the first clock and does not require clock-names. */
	i = 0;
	if (name != NULL) {
		count = of_property_count_strings(dev->of_node, "clock-names");
		if (count < 0)
			return (ERR_PTR(count));
		for (i = 0; i < count; i++) {
			error = of_property_read_string_index(dev->of_node,
			    "clock-names", i, &entry);
			if (error != 0)
				return (ERR_PTR(error));
			if (strcmp(entry, name) == 0)
				break;
		}
		if (i == count)
			return (NULL);
	}
	clk = kzalloc(sizeof(*clk), GFP_KERNEL);
	if (clk == NULL)
		return (ERR_PTR(-ENOMEM));
	error = clk_get_by_ofw_index(dev->bsddev, dev->of_node->bsd_node, i, &clk->native);
	if (error != 0) {
		kfree(clk);
		return (ERR_PTR(-error));
	}
	error = clk_get_freq(clk->native, &frequency);
	if (error != 0 || frequency != rate)
		error = clk_set_freq(clk->native, rate, CLK_SET_ROUND_EXACT);
	if (error == 0)
		error = clk_enable(clk->native);
	if (error != 0) {
		clk_release(clk->native);
		kfree(clk);
		return (ERR_PTR(-error));
	}
	error = devm_add_action_or_reset(dev, lkpi_clk_release, clk);
	return (error == 0 ? clk : ERR_PTR(error));
#else
	(void)dev;
	(void)name;
	(void)rate;
	return (NULL);
#endif
}
