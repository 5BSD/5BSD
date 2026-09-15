/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LINUXKPI_LINUX_OF_IRQ_H_
#define _LINUXKPI_LINUX_OF_IRQ_H_
#include <linux/errno.h>
#include <linux/of.h>
struct of_phandle_args {
	struct device_node *np;
	int args_count;
	u32 args[16];
};
/* Native OF interrupt resources are not yet exposed as Linux IRQ numbers. */
static inline int
of_irq_parse_one(struct device_node *np, int index, struct of_phandle_args *args)
{
	(void)np;
	(void)index;
	(void)args;
	return (-EOPNOTSUPP);
}
static inline unsigned int
irq_create_of_mapping(struct of_phandle_args *args)
{
	(void)args;
	return (0);
}
static inline unsigned int
irq_get_trigger_type(unsigned int irq)
{
	/* No OF interrupt mapping is currently exported by this adapter. */
	(void)irq;
	return (0);
}
#endif
