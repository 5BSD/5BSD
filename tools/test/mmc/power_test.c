/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifndef __unused
#define __unused __attribute__((unused))
#endif

typedef void *device_t;
enum mmc_power_mode { power_off, power_up, power_on };
enum { bus_width_1, bus_width_4, bus_width_8, bus_timing_hs };
struct resource { char on, off; int refs, enable_error, disable_error; };
struct gpio { bool active; int assert_error, release_error; };
struct mmc_pwrseq_softc {
	struct resource *ext_clock;
	bool clock_enabled;
	struct gpio *reset_gpio;
	unsigned post_power_on_delay_ms, power_off_delay_us;
};
struct mmc_helper {
	struct resource *vmmc_supply, *vqmmc_supply;
	device_t mmc_pwrseq;
};
struct bcm_sdhci_softc {
	struct mmc_helper sc_mmc_helper;
	bool sc_vmmc_enabled, sc_vqmmc_enabled, sc_pwrseq_on;
};
struct mmc_ios {
	int power_mode, clock, vdd, bus_width, timing, chip_select, bus_mode, vccq;
};
#define MMC_PM (1u << 0)
#define MMC_CLK (1u << 1)
#define MMC_VDD (1u << 2)
#define MMC_CS (1u << 3)
#define MMC_BW (1u << 4)
#define MMC_BT (1u << 5)
#define MMC_BM (1u << 6)
#define MMC_VCCQ (1u << 7)
struct ccb_trans_settings_mmc {
	unsigned host_ocr, host_f_min, host_f_max, host_caps, host_max_data;
	struct mmc_ios ios;
	unsigned ios_valid;
};
struct ccb_hdr { int status, func_code; };
struct ccb_trans_settings {
	struct ccb_hdr ccb_h;
	int protocol, protocol_version, transport, transport_version;
	struct { int valid; } xport_specific;
	struct { struct ccb_trans_settings_mmc mmc; } proto_specific;
};
union ccb {
	struct ccb_hdr ccb_h;
	struct ccb_trans_settings cts;
	struct { struct ccb_hdr ccb_h; } cpi;
};
struct task { int unused; };
struct sdhci_slot {
	struct { struct mmc_ios ios; unsigned host_ocr, f_min, f_max, caps; } host;
	device_t bus;
	unsigned hostctrl, quirks, opt, retune_mode;
	int sim_mtx, lock;
	union ccb *ios_ccb, *ccb;
	struct task ios_task;
	bool cam_stopping;
};
static struct sdhci_slot slot;
static struct bcm_sdhci_softc bcm;
static struct mmc_pwrseq_softc seq;
static struct resource vmmc, vqmmc, clock_source;
static struct gpio reset_gpio;
static char events[128];
static int completed;
static int sdhci_debug;
static int queued, enqueue_error, io_requests;
struct cam_sim { struct sdhci_slot *slot; };
#define cam_sim_softc(sim) ((sim)->slot)
#define MA_OWNED 1
#define mtx_assert(lock, condition) assert(*(lock) && (condition) == MA_OWNED)
#ifndef __predict_false
#define __predict_false(x) (x)
#endif
#define maxphys 65536
#define MMC_SECTOR_SIZE 512
#define SDHCI_TUNING_ENABLED 1
#define SDHCI_RETUNE_MODE_1 1
#define SDHCI_RETUNE_MODE_2 2
#define PROTO_MMCSD 0
#define XPORT_MMCSD 0
#define mmc_path_inq(...) ((void)0)
enum { XPT_PATH_INQ, XPT_MMC_GET_TRAN_SETTINGS, XPT_GET_TRAN_SETTINGS,
    XPT_MMC_SET_TRAN_SETTINGS, XPT_SET_TRAN_SETTINGS, XPT_RESET_BUS, XPT_MMC_IO };
#define taskqueue_thread NULL
static int taskqueue_enqueue(void *queue, struct task *task) {
	(void)queue; assert(task == &slot.ios_task); assert(slot.sim_mtx);
	queued++; return enqueue_error;
}
static int sdhci_cam_request(struct sdhci_slot *s, union ccb *c) {
	assert(s->sim_mtx && !s->ios_ccb); s->ccb = c; io_requests++; return 0;
}

static void event(char c) {
	size_t n = strlen(events);
	assert(n + 1 < sizeof(events)); events[n] = c; events[n + 1] = 0;
}
static void unlocked(void) { assert(!slot.lock && !slot.sim_mtx); }
static int enable(struct resource *r) {
	unlocked(); if (r->enable_error) return r->enable_error;
	r->refs++; event(r->on); return 0;
}
static int disable(struct resource *r) {
	unlocked(); assert(r->refs > 0);
	if (r->disable_error) return r->disable_error;
	r->refs--; event(r->off); return 0;
}
#define clk_enable enable
#define clk_disable disable
#define regulator_enable enable
#define regulator_disable disable
#define device_get_softc(d) (d)
#define device_get_ivars(d) (d)
#define device_printf(...) ((void)0)
#define slot_printf(...) ((void)0)
#define DELAY(n) ((void)(n))
static int gpio_pin_set_active(struct gpio *g, bool active) {
	int error = active ? g->assert_error : g->release_error;
	unlocked(); if (error) return error;
	g->active = active; event(active ? 'R' : 'r'); return 0;
}
static void mtx_lock(int *lock) { assert(!*lock); *lock = 1; }
static void mtx_unlock(int *lock) { assert(*lock); *lock = 0; }
#define SDHCI_LOCK(s) mtx_lock(&(s)->lock)
#define SDHCI_UNLOCK(s) mtx_unlock(&(s)->lock)
#define SDHCI_SIGNAL_ENABLE 0
#define SDHCI_HOST_CONTROL 0
#define SDHCI_CTRL_8BITBUS 1
#define SDHCI_CTRL_4BITBUS 2
#define SDHCI_CTRL_HISPD 4
#define SDHCI_QUIRK_DONT_SET_HISPD_BIT 1
#define SDHCI_QUIRK_RESET_ON_IOS 2
#define SDHCI_RESET_CMD 1
#define SDHCI_RESET_DATA 2
#define SD_SDR12_MAX 25000000
#define WR1(s, r, v) do { assert((s)->lock); (void)(r); (void)(v); } while (0)
#define WR4 WR1
#define SDHCI_SET_UHS_TIMING(d, s) do { (void)(d); assert((s)->lock); } while (0)
#define SDHCI_RESET(d, s, m) do { (void)(d); (void)(m); assert((s)->lock); } while (0)
#define panic(...) assert(false)
static void sdhci_init(struct sdhci_slot *s) { assert(s->lock); }
static void sdhci_set_clock(struct sdhci_slot *s, int clock) {
	(void)clock; assert(s->lock);
}
static void sdhci_set_power(struct sdhci_slot *s, int voltage) {
	assert(s->lock); event(voltage ? 'P' : 'p');
}
#define MMC_PWRSEQ_SET_POWER mmv_pwrseq_set_power
#define SDHCI_PLATFORM_SET_POWER bcm_sdhci_set_power
#define CAM_REQ_CMP 1
#define CAM_REQ_CMP_ERR 2
#define CAM_DEV_NOT_THERE 3
#define CAM_BUSY 4
#define CAM_RESRC_UNAVAIL 5
#define CAM_REQ_INPROG 6
#define CAM_SEL_TIMEOUT 7
#define CAM_REQ_INVALID 8
static int sdhci_cam_update_ios(struct sdhci_slot *, bool);
static int sdhci_cam_get_possible_host_clock(const struct sdhci_slot *s, int clock) {
	(void)s; return clock;
}
static void xpt_done(union ccb *c) {
	assert(slot.sim_mtx && !slot.lock && slot.ios_ccb != c);
	assert(c->ccb_h.status >= CAM_REQ_CMP && c->ccb_h.status <= CAM_REQ_INVALID);
	completed++;
}

/* The runner emits these functions directly from the kernel source. */
#include "sdt_test.h"
#include "power_functions.h"

static void reset(void) {
	memset(&slot, 0, sizeof(slot)); memset(&bcm, 0, sizeof(bcm));
	memset(&seq, 0, sizeof(seq)); memset(&reset_gpio, 0, sizeof(reset_gpio));
	vmmc = (struct resource){ .on = 'V', .off = 'v' };
	vqmmc = (struct resource){ .on = 'Q', .off = 'q' };
	clock_source = (struct resource){ .on = 'C', .off = 'c' };
	seq.ext_clock = &clock_source; seq.reset_gpio = &reset_gpio;
	reset_gpio.active = true;
	bcm.sc_mmc_helper = (struct mmc_helper){ &vmmc, &vqmmc, &seq };
	slot.bus = &bcm; slot.host.ios.vdd = 1;
	completed = 0; events[0] = 0;
	queued = enqueue_error = io_requests = 0;
}
static void expect(const char *text) {
	if (strcmp(events, text)) fprintf(stderr, "events '%s', expected '%s'\n", events, text);
	assert(strcmp(events, text) == 0); events[0] = 0;
}
static int update(bool cam, enum mmc_power_mode mode) {
	slot.host.ios.power_mode = mode;
	return cam ? sdhci_cam_update_ios(&slot, true) : sdhci_generic_update_ios(&bcm, &slot);
}
static void power_tests(bool cam) {
	reset(); assert(update(cam, power_off) == 0); expect("pR");
	assert(update(cam, power_up) == 0); expect("VQCrP");
	assert(update(cam, power_up) == 0); expect("P");
	assert(update(cam, power_on) == 0); expect("P");
	assert(update(cam, power_off) == 0); expect("pRcqv");
	assert(vmmc.refs == 0 && vqmmc.refs == 0 && clock_source.refs == 0);
	assert(update(cam, power_off) == 0); expect("pR");
	/* Drop only references owned by this host, preserving other consumers. */
	reset(); vmmc.refs = vqmmc.refs = 1;
	assert(update(cam, power_up) == 0); assert(update(cam, power_off) == 0);
	assert(vmmc.refs == 1 && vqmmc.refs == 1);
	reset(); vmmc.enable_error = EIO;
	assert(update(cam, power_up) == EIO); expect("");
	reset(); vqmmc.enable_error = EIO;
	assert(update(cam, power_up) == EIO); expect("VRv"); assert(vmmc.refs == 0);
	reset(); clock_source.enable_error = EIO;
	assert(update(cam, power_up) == EIO); expect("VQRqv");
	reset(); reset_gpio.release_error = EIO;
	assert(update(cam, power_up) == EIO); expect("VQCcRqv");
	assert(!seq.clock_enabled && !bcm.sc_vmmc_enabled && !bcm.sc_vqmmc_enabled);
	reset_gpio.release_error = 0;
	assert(update(cam, power_up) == 0); expect("VQCrP");
	/* Do not cut the rails if asserting reset fails; retry remains possible. */
	reset_gpio.assert_error = EIO;
	assert(update(cam, power_off) == EIO); expect("p");
	assert(vmmc.refs == 1 && vqmmc.refs == 1 && clock_source.refs == 1);
	reset_gpio.assert_error = 0;
	assert(update(cam, power_off) == 0); expect("pRcqv");
	reset(); assert(update(cam, power_up) == 0); events[0] = 0;
	clock_source.disable_error = EIO;
	assert(update(cam, power_off) == EIO); expect("pR"); assert(seq.clock_enabled);
	clock_source.disable_error = 0;
	/* Restart after a partial stop must release the already asserted reset. */
	assert(update(cam, power_up) == 0); expect("rP"); assert(!reset_gpio.active);
	assert(update(cam, power_off) == 0); expect("pRcqv");
	reset(); assert(update(cam, power_up) == 0); events[0] = 0;
	vqmmc.disable_error = EIO;
	assert(update(cam, power_off) == EIO); expect("pRc");
	assert(bcm.sc_vqmmc_enabled && bcm.sc_vmmc_enabled);
	vqmmc.disable_error = 0;
	assert(update(cam, power_off) == 0); expect("pRqv");
	/* No DT supplies or power sequence is a valid host configuration. */
	reset(); memset(&bcm.sc_mmc_helper, 0, sizeof(bcm.sc_mmc_helper));
	assert(update(cam, power_up) == 0); expect("P");
	assert(update(cam, power_off) == 0); expect("p");
}
static void worker_tests(void) {
	union ccb c = {0};
	reset(); slot.ios_ccb = &c;
	c.cts.proto_specific.mmc.ios_valid = MMC_PM;
	c.cts.proto_specific.mmc.ios.power_mode = power_up;
	sdhci_cam_ios_task(&slot, 0); expect("VQCrP");
	assert(completed == 1 && c.ccb_h.status == CAM_REQ_CMP);
	sdhci_cam_ios_task(&slot, 0); assert(completed == 1);
	reset(); slot.ios_ccb = &c; vmmc.enable_error = EIO;
	sdhci_cam_ios_task(&slot, 0);
	assert(completed == 1 && c.ccb_h.status == CAM_REQ_CMP_ERR);
	reset(); slot.ios_ccb = &c; slot.cam_stopping = true;
	sdhci_cam_ios_task(&slot, 0);
	assert(completed == 1 && !bcm.sc_vmmc_enabled && c.ccb_h.status == CAM_REQ_CMP_ERR);
}
static void action_tests(void) {
	struct cam_sim sim = { &slot };
	union ccb c = {0}, other = {0};
	reset(); c.cts.proto_specific.mmc.ios_valid = MMC_PM;
	c.cts.proto_specific.mmc.ios.power_mode = power_up;
	c.ccb_h.func_code = XPT_MMC_SET_TRAN_SETTINGS;
	mtx_lock(&slot.sim_mtx); sdhci_cam_action(&sim, &c);
	assert(slot.ios_ccb == &c && queued == 1 && completed == 0);
	other.ccb_h.func_code = XPT_SET_TRAN_SETTINGS;
	sdhci_cam_action(&sim, &other);
	assert(other.ccb_h.status == CAM_BUSY && queued == 1 && slot.ios_ccb == &c);
	other.ccb_h.func_code = XPT_MMC_IO;
	sdhci_cam_action(&sim, &other);
	assert(other.ccb_h.status == CAM_BUSY && io_requests == 0);
	other.ccb_h.func_code = XPT_MMC_GET_TRAN_SETTINGS;
	sdhci_cam_action(&sim, &other); assert(other.ccb_h.status == CAM_BUSY);
	mtx_unlock(&slot.sim_mtx);
	sdhci_cam_ios_task(&slot, 0);
	assert(completed == 4 && c.ccb_h.status == CAM_REQ_CMP);
	reset(); slot.ccb = &other;
	mtx_lock(&slot.sim_mtx); sdhci_cam_action(&sim, &c);
	assert(c.ccb_h.status == CAM_BUSY && queued == 0 && slot.ccb == &other);
	mtx_unlock(&slot.sim_mtx);
	reset(); enqueue_error = EIO;
	mtx_lock(&slot.sim_mtx); sdhci_cam_action(&sim, &c);
	assert(c.ccb_h.status == CAM_RESRC_UNAVAIL && !slot.ios_ccb && completed == 1);
	mtx_unlock(&slot.sim_mtx);
	reset(); slot.cam_stopping = true;
	mtx_lock(&slot.sim_mtx); sdhci_cam_action(&sim, &c);
	assert(c.ccb_h.status == CAM_DEV_NOT_THERE && queued == 0 && completed == 1);
	mtx_unlock(&slot.sim_mtx);
	/* Synchronous callers can immediately reuse the CCB for another setting. */
	for (int mode = power_off; mode <= power_on; mode++) {
		reset(); slot.host.ios.power_mode = mode;
		c.ccb_h.func_code = XPT_SET_TRAN_SETTINGS;
		c.cts.proto_specific.mmc.ios_valid = MMC_CLK;
		c.cts.proto_specific.mmc.ios.clock = 25000000;
		mtx_lock(&slot.sim_mtx); sdhci_cam_action(&sim, &c);
		assert(!slot.ios_ccb && queued == 0 && completed == 1);
		assert(c.ccb_h.status == CAM_REQ_CMP);
		assert(slot.host.ios.clock == 25000000);
		c.cts.proto_specific.mmc.ios_valid = MMC_BW;
		c.cts.proto_specific.mmc.ios.bus_width = bus_width_4;
		sdhci_cam_action(&sim, &c);
		assert(c.ccb_h.status == CAM_REQ_CMP && completed == 2);
		assert(slot.host.ios.bus_width == bus_width_4);
		assert(!slot.ios_ccb && queued == 0);
		mtx_unlock(&slot.sim_mtx);
		/* No regulator, clock-provider or GPIO calls for ordinary settings. */
		expect(mode == power_off ? "pp" : "PP");
	}
	/* Reject synchronous power requests before mutating any IOS fields. */
	reset(); c.ccb_h.func_code = XPT_SET_TRAN_SETTINGS;
	c.cts.proto_specific.mmc.ios_valid = MMC_PM | MMC_CLK;
	c.cts.proto_specific.mmc.ios.power_mode = power_up;
	c.cts.proto_specific.mmc.ios.clock = 400000;
	mtx_lock(&slot.sim_mtx); sdhci_cam_action(&sim, &c);
	assert(c.ccb_h.status == CAM_REQ_INVALID && completed == 1);
	assert(slot.host.ios.power_mode == power_off && slot.host.ios.clock == 0);
	assert(!slot.ios_ccb && queued == 0);
	mtx_unlock(&slot.sim_mtx); expect("");

}
int main(void) {
	power_tests(false); power_tests(true); worker_tests(); action_tests();
	/* Power rollback nests a power-off inside power-up; pairs stay balanced. */
	unsigned depth = 0, maximum = 0;
	uintptr_t modes[8];
	for (unsigned i = 0; i < sdt_count; i++) {
		assert(sdt_events[i].args[0] == (uintptr_t)&bcm);
		if (strcmp(sdt_events[i].name, "power__start") == 0) {
			assert(depth < 8); modes[depth++] = sdt_events[i].args[1];
			if (depth > maximum) maximum = depth;
		} else {
			assert(strcmp(sdt_events[i].name, "power__done") == 0);
			assert(depth > 0 && modes[--depth] == sdt_events[i].args[1]);
		}
	}
	assert(depth == 0 && maximum == 2);
	puts("PASS: legacy/CAM ordering, idempotence, rollback, retries, shared supplies, unlocked worker, CAM serialization and completion");
	return 0;
}
