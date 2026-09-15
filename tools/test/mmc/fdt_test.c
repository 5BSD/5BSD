/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int phandle_t;
typedef void *device_t;
struct mmc_helper { unsigned props; void *vmmc_supply, *vqmmc_supply; device_t mmc_pwrseq; };
struct mmc_host { unsigned caps; };
static int bootverbose;
static int device_node, property_node, property_size, regulator_calls;
static bool property_present, provider_ready;
static phandle_t ofw_bus_get_node(device_t d) { (void)d; return device_node; }
static int OF_hasprop(phandle_t n, const char *p) { (void)p; return n == property_node && property_present; }
static int OF_getencprop(phandle_t n, const char *p, void *out, int size) {
 (void)p; assert(n == property_node); assert(size == sizeof(phandle_t));
 if (property_size == size) *(phandle_t *)out = 123;
 return property_size;
}
static device_t OF_device_from_xref(phandle_t p) { assert(p == 123); return provider_ready ? (void *)2 : NULL; }
#define device_printf(...) ((void)0)
static void mmc_parse(device_t d, struct mmc_helper *h, struct mmc_host *host) {
 (void)d; (void)host; h->props = 42;
}
static int regulator_get_by_ofw_property(device_t d, int i, const char *p, void **out) {
 (void)d; (void)i; (void)p; *out = NULL; regulator_calls++; return ENOENT;
}
static int regulator_check_voltage(void *r, int v) { (void)r; (void)v; return 0; }
#define MMC_CAP_MMC_DDR52_120 (1u << 0)
#define MMC_CAP_MMC_DDR52_180 (1u << 1)
#define MMC_CAP_MMC_HS200_120 (1u << 2)
#define MMC_CAP_MMC_HS200_180 (1u << 3)
#define MMC_CAP_MMC_HS400_120 (1u << 4)
#define MMC_CAP_MMC_HS400_180 (1u << 5)
#define MMC_CAP_SIGNALING_120 (1u << 6)
#define MMC_CAP_SIGNALING_180 (1u << 7)
#define MMC_CAP_SIGNALING_330 (1u << 8)
#define MMC_CAP_UHS_DDR50 (1u << 9)
#define MMC_CAP_UHS_SDR104 (1u << 10)
#define MMC_CAP_UHS_SDR25 (1u << 11)
#define MMC_CAP_UHS_SDR50 (1u << 12)

/* Exercise a real caller, including freeing its slot on parser failure. */
#define MMC_PROP_WP_INVERTED 1
#define MMC_PROP_NON_REMOVABLE 2
#define SDHCI_NON_REMOVABLE 1
#define M_DEVBUF 0
#define M_ZERO 1
#define M_WAITOK 2
struct sdhci_slot {
	struct mmc_host host;
	unsigned opt;
};
struct sdhci_xenon_softc {
	bool skip_regulators, wp_inverted;
	void *vmmc_supply, *vqmmc_supply, *gpio;
	struct sdhci_slot *slot;
};
static struct sdhci_xenon_softc xenon;
static unsigned allocations, gpio_setups, controller_attaches;
static void *
slot_alloc(size_t size, int type, int flags)
{
	(void)type;
	assert(flags == (M_ZERO | M_WAITOK));
	allocations++;
	return (calloc(1, size));
}
static void
slot_free(void *slot, int type)
{
	(void)type;
	assert(allocations > 0);
	allocations--;
	free(slot);
}
static void *
sdhci_fdt_gpio_setup(device_t dev, struct sdhci_slot *slot)
{
	(void)dev;
	assert(slot != NULL);
	gpio_setups++;
	return (slot);
}
static int
sdhci_xenon_attach(device_t dev)
{
	(void)dev;
	controller_attaches++;
	return (0);
}
#define device_get_softc(dev) ((void)(dev), &xenon)
#define malloc slot_alloc
#define free slot_free
#include "power_functions.h"
#undef malloc
#undef free

static void reset(void) {
 device_node = 17; property_node = 17; property_size = sizeof(phandle_t);
 property_present = true; provider_ready = true; regulator_calls = 0;
}
static void attach_tests(void) {
 for (int failure = 0; failure < 3; failure++) {
  reset();
  memset(&xenon, 0, sizeof(xenon));
  if (failure == 0) device_node = -1;
  if (failure == 1) property_size = 0;
  if (failure == 2) provider_ready = false;
  assert(sdhci_xenon_fdt_attach((void *)1) == ENXIO);
  assert(allocations == 0 && regulator_calls == 0);
  assert(gpio_setups == 0 && controller_attaches == 0);
  assert(xenon.slot == NULL);
 }
 /* A subsequent attempt with the provider ready can attach normally. */
 reset();
 assert(sdhci_xenon_fdt_attach((void *)1) == 0);
 assert(allocations == 1 && regulator_calls == 2);
 assert(gpio_setups == 1 && controller_attaches == 1);
 slot_free(xenon.slot, M_DEVBUF);
}
int main(void) {
 struct mmc_helper h = {0}; struct mmc_host host = {0};
 reset(); assert(mmc_fdt_parse((void *)1, 0, &h, &host) == 0);
 assert(h.mmc_pwrseq == (void *)2); assert(h.props == 42); assert(regulator_calls == 2);
 reset(); property_node = 23; assert(mmc_fdt_parse((void *)1, 23, &h, &host) == 0);
 assert(h.mmc_pwrseq == (void *)2);
 reset(); property_present = false; h.mmc_pwrseq = (void *)3;
 assert(mmc_fdt_parse((void *)1, 0, &h, &host) == 0); assert(h.mmc_pwrseq == NULL);
 for (int n = -1; n <= 5; n++) {
  if (n == sizeof(phandle_t)) continue;
  reset(); property_size = n;
  assert(mmc_fdt_parse((void *)1, 0, &h, &host) == ENXIO); assert(regulator_calls == 0);
 }
 memset(&h, 0, sizeof(h)); memset(&host, 0, sizeof(host));
 reset(); provider_ready = false;
 assert(mmc_fdt_parse((void *)1, 0, &h, &host) == ENXIO); assert(regulator_calls == 0);
 assert(h.props == 0 && host.caps == 0);
 provider_ready = true;
 assert(mmc_fdt_parse((void *)1, 0, &h, &host) == 0); assert(h.mmc_pwrseq == (void *)2);
 reset(); device_node = -1;
 assert(mmc_fdt_parse((void *)1, 0, &h, &host) == ENXIO); assert(regulator_calls == 0);
 attach_tests();
 puts("PASS: default/explicit node, absent/malformed property, missing provider/retry, invalid node, attach failure cleanup");
}
