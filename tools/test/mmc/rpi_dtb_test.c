/* SPDX-License-Identifier: BSD-2-Clause */
/* Apply the shipped overlays to actual firmware DTBs before boot testing. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libfdt.h>

static void *read_blob(const char *path)
{
	FILE *file = fopen(path, "rb");
	if (file == NULL) { perror(path); exit(1); }
	assert(fseek(file, 0, SEEK_END) == 0);
	long size = ftell(file);
	assert(size > 0 && size < 1024 * 1024);
	void *data = malloc(size);
	assert(data != NULL && fseek(file, 0, SEEK_SET) == 0);
	assert(fread(data, 1, size, file) == (size_t)size);
	fclose(file);
	assert(fdt_check_header(data) == 0 && fdt_totalsize(data) <= (unsigned)size);
	return data;
}

static int symbol(void *tree, const char *name)
{
	int symbols = fdt_path_offset(tree, "/__symbols__");
	const char *path = fdt_getprop(tree, symbols, name, NULL);
	assert(path != NULL);
	int node = fdt_path_offset(tree, path);
	assert(node >= 0);
	return node;
}

static void enabled(void *tree, int node)
{
	const char *status = fdt_getprop(tree, node, "status", NULL);
	assert(status == NULL || strcmp(status, "okay") == 0 || strcmp(status, "ok") == 0);
}

/* Follow the native pinctrl walk: enabled children first, then the parent.
 * Check the actual tuples consumed by bcm_gpio_configure_pins(), not just
 * phandle names, and detect later pin groups overriding the radio route. */
static void pinmux(void *tree, int parent, int controller, int functions[64])
{
	int node;
	fdt_for_each_subnode(node, tree, parent) {
		const char *status = fdt_getprop(tree, node, "status", NULL);
		if (status && strcmp(status, "okay") && strcmp(status, "ok"))
			continue;
		pinmux(tree, node, controller, functions);
		int length;
		const fdt32_t *groups = fdt_getprop(tree, node, "pinctrl-0", &length);
		if (!groups) continue;
		assert(length % 4 == 0);
		for (int i = 0; i < length / 4; i++) {
			int group = fdt_node_offset_by_phandle(tree, fdt32_to_cpu(groups[i]));
			assert(group >= 0);
			if (fdt_parent_offset(tree, group) != controller) continue;
			int pinslen, fnlen, pullslen;
			const fdt32_t *pins = fdt_getprop(tree, group, "brcm,pins", &pinslen);
			const fdt32_t *fn = fdt_getprop(tree, group, "brcm,function", &fnlen);
			const fdt32_t *pulls = fdt_getprop(tree, group, "brcm,pull", &pullslen);
			assert(pins && pinslen % 4 == 0);
			if (pinslen == 0) continue;
			assert(fn && fnlen == 4 && fdt32_to_cpu(*fn) < 8);
			/* Native BCM pinctrl rejects mismatched pull arrays. */
			if (pulls && pullslen != pinslen) continue;
			for (int j = 0; j < pinslen / 4; j++) {
				unsigned pin = fdt32_to_cpu(pins[j]);
				assert(pin < 64);
				functions[pin] = fdt32_to_cpu(*fn);
			}
		}
	}
}

int main(int argc, char **argv)
{
	assert(argc == 4); /* base, disable-bt, board Wi-Fi overlay */
	void *base = read_blob(argv[1]);
	void *tree = malloc(1024 * 1024);
	assert(tree && fdt_open_into(base, tree, 1024 * 1024) == 0);
	free(base);
	for (int i = 2; i < argc; i++) {
		void *overlay = read_blob(argv[i]);
		int error = fdt_overlay_apply(tree, overlay);
		if (error) { fprintf(stderr, "%s: %s\n", argv[i], fdt_strerror(error)); return 1; }
		free(overlay);
	}
	bool pi4 = fdt_node_check_compatible(tree, 0, "raspberrypi,4-model-b") == 0;
	assert(pi4 || fdt_node_check_compatible(tree, 0, "raspberrypi,model-zero-2-w") == 0);
	int wifi = symbol(tree, "mmcnr");
	for (int ancestor = wifi; ancestor >= 0; ancestor = fdt_parent_offset(tree, ancestor))
		enabled(tree, ancestor);
	/* The alternate description of the same controller must stay disabled. */
	int alias = symbol(tree, "mmc");
	assert(alias != wifi);
	const char *alias_status = fdt_getprop(tree, alias, "status", NULL);
	assert(alias_status && strcmp(alias_status, "disabled") == 0);
	assert(fdt_node_check_compatible(tree, wifi, "brcm,bcm2835-sdhci") == 0);
	assert(fdt_getprop(tree, wifi, "non-removable", NULL));
	int child = fdt_subnode_offset(tree, wifi, "wifi@1");
	assert(child >= 0);
	const fdt32_t *reg = fdt_getprop(tree, child, "reg", NULL);
	assert(reg && fdt32_to_cpu(*reg) == 1);
	const fdt32_t *power = fdt_getprop(tree, wifi, "mmc-pwrseq", NULL);
	assert(power);
	int seq = fdt_node_offset_by_phandle(tree, fdt32_to_cpu(*power));
	assert(seq >= 0 && fdt_node_check_compatible(tree, seq, "mmc-pwrseq-simple") == 0);
	int size;
	const fdt32_t *gpio = fdt_getprop(tree, seq, "reset-gpios", &size);
	assert(gpio && size == 12 && fdt32_to_cpu(gpio[1]) == (pi4 ? 1 : 41));
	assert(fdt32_to_cpu(gpio[2]) == 1); /* active low */
	assert(fdt_node_offset_by_phandle(tree, fdt32_to_cpu(gpio[0])) == symbol(tree, pi4 ? "expgpio" : "gpio"));
	enabled(tree, symbol(tree, pi4 ? "emmc2" : "sdhost"));
	if (!pi4) {
		const fdt32_t *pins = fdt_getprop(tree, wifi, "pinctrl-0", &size);
		assert(pins && size == 8);
		assert(fdt_node_offset_by_phandle(tree, fdt32_to_cpu(pins[1])) == symbol(tree, "gpclk2_gpio43"));
	}
	int functions[64];
	for (unsigned i = 0; i < 64; i++) functions[i] = -1;
	pinmux(tree, 0, symbol(tree, "gpio"), functions);
	for (unsigned pin = 34; pin <= 39; pin++) assert(functions[pin] == 7);
	assert(functions[14] == 4 && functions[15] == 4); /* PL011 console */
	if (!pi4) {
		assert(functions[43] == 4); /* GPCLK2 LPO */
		for (unsigned pin = 48; pin <= 53; pin++) assert(functions[pin] == 4);
	}
	free(tree);
	puts("PASS: applied DT keeps SD card and Wi-Fi enabled, resolves reset provider and validates effective SDIO/clock/console pins");
	return 0;
}
