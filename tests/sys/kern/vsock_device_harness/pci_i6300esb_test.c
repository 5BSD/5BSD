/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include coverage harness for bhyve's Intel 6300ESB PCI watchdog device
 * (usr.sbin/bhyve/pci_i6300esb.c).  The device source is compiled directly
 * into the test so its static entry points can be driven without a running VM.
 * The bhyve/vmmapi infrastructure it depends on (pci_emul, mevent, vm_suspend/
 * vm_inject_nmi, config nvlist, snapshot codec) is replaced with independent
 * mocks defined below.  Assertions are checked against the documented i6300ESB
 * register/BAR layout, the datasheet two-stage timer semantics, and the
 * documented "-s ...,i6300esb" option contract -- never against the
 * implementation's own output.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

/*
 * ---- Neutralize the kernel / vmmapi header maze -----------------------------
 * pci_i6300esb.c pulls in <machine/vmm.h> and <vmmapi.h>.  Pre-defining their
 * include guards turns those includes into no-ops so the device sees the
 * minimal, self-contained declarations provided here.  <machine/vmm_snapshot.h>
 * is deliberately left real: it supplies the snapshot metadata types and the
 * SNAPSHOT_BUF_OR_LEAVE macro the codec uses.
 */
#define	_VMM_H_
#define	_VMMAPI_H_

typedef uint64_t vm_paddr_t;
struct vmctx { int dummy; };
struct vcpu { int vcpuid; };

/* Mirror the real enum ordering so VM_SUSPEND_* values match the datasheet. */
enum vm_suspend_how {
	VM_SUSPEND_NONE,
	VM_SUSPEND_RESET,
	VM_SUSPEND_POWEROFF,
	VM_SUSPEND_HALT,
	VM_SUSPEND_TRIPLEFAULT,
	VM_SUSPEND_DESTROY,
	VM_SUSPEND_LAST
};

int vm_suspend(struct vmctx *, enum vm_suspend_how);
int vm_inject_nmi(struct vcpu *);
struct vcpu *vm_vcpu_open(struct vmctx *, int);

/*
 * Harness mock headers for config/debug/mevent/snapshot.  After each mock is
 * pulled in, define the *real* bhyve header's include guard so that when
 * pci_i6300esb.c later quote-includes it by name -- resolving to the real
 * header in its own directory first -- it sees the mock already in place.
 */
#include "config.h"
#define	__CONFIG_H__		/* block real usr.sbin/bhyve/config.h */
#include "debug.h"
#define	_DEBUG_H_		/* block real usr.sbin/bhyve/debug.h */
#include "mevent.h"
#define	_MEVENT_H_		/* block real usr.sbin/bhyve/mevent.h */
#include <machine/vmm_snapshot.h>
#include "snapshot.h"
#define	_BHYVE_SNAPSHOT_	/* block real usr.sbin/bhyve/snapshot.h */

/*
 * ---- pci_emul mock ----------------------------------------------------------
 * Block both the harness mock pci_emul.h and the real bhyve header and provide
 * a device-accurate subset.  <dev/pci/pcireg.h> is left real: it supplies the
 * PCIR and PCIM register offsets the device programs.
 */
#define	MOCK_PCI_EMUL_H
#define	_PCI_EMUL_H_

enum pcibar_type {
	PCIBAR_NONE,
	PCIBAR_IO,
	PCIBAR_MEM32,
	PCIBAR_MEM64,
	PCIBAR_MEMHI64,
	PCIBAR_ROM,
};
struct pcibar {
	enum pcibar_type type;
	uint64_t size;
	uint64_t addr;
};
struct pci_devinst {
	struct pci_devemu *pi_d;
	struct vmctx *pi_vmctx;
	void *pi_arg;
	struct pcibar pi_bar[7];
	uint8_t pi_cfgdata[256];
};
struct pci_devemu {
	const char *pe_emu;
	int (*pe_init)(struct pci_devinst *, nvlist_t *);
	void (*pe_barwrite)(struct pci_devinst *, int, uint64_t, int, uint64_t);
	uint64_t (*pe_barread)(struct pci_devinst *, int, uint64_t, int);
	int (*pe_cfgwrite)(struct pci_devinst *, int, int, uint32_t);
	int (*pe_cfgread)(struct pci_devinst *, int, int, uint32_t *);
	int (*pe_snapshot)(struct vm_snapshot_meta *);
	int (*pe_snapshot_validate)(struct vm_snapshot_meta *);
};
#define	PCI_EMUL_SET(x)

void pci_set_cfgdata8(struct pci_devinst *, int, uint8_t);
void pci_set_cfgdata16(struct pci_devinst *, int, uint16_t);
int pci_emul_alloc_bar(struct pci_devinst *, int, enum pcibar_type, uint64_t);
void pci_lintr_request(struct pci_devinst *);
void pci_lintr_assert(struct pci_devinst *);
void pci_lintr_deassert(struct pci_devinst *);

/* ---- mock control state ---------------------------------------------------- */
static unsigned g_suspend_calls;
static enum vm_suspend_how g_last_suspend_how;
static int g_suspend_ret;
static int g_suspend_errno;

static unsigned g_nmi_calls;
static struct vcpu *g_last_nmi_vcpu;
static int g_nmi_ret;

static struct vcpu g_bsp_vcpu = { .vcpuid = 0 };
static unsigned g_vcpu_open_calls;

static bool g_alloc_bar_fail;
static unsigned g_lintr_request_calls;
static unsigned g_lintr_assert_calls;
static unsigned g_lintr_deassert_calls;
static int g_lintr_state;	/* net asserted (asserts - deasserts) */

static int g_mevent_token;	/* opaque handle sentinel */
static unsigned g_mevent_add_calls;
static unsigned g_mevent_update_calls;
static unsigned g_mevent_delete_calls;
static int g_last_arm_ms;

/* ---- vmmapi mock ----------------------------------------------------------- */
int
vm_suspend(struct vmctx *ctx __unused, enum vm_suspend_how how)
{

	g_suspend_calls++;
	g_last_suspend_how = how;
	if (g_suspend_ret != 0)
		errno = g_suspend_errno;
	return (g_suspend_ret);
}

int
vm_inject_nmi(struct vcpu *vcpu)
{

	g_nmi_calls++;
	g_last_nmi_vcpu = vcpu;
	return (g_nmi_ret);
}

struct vcpu *
vm_vcpu_open(struct vmctx *ctx __unused, int vcpuid __unused)
{

	g_vcpu_open_calls++;
	return (&g_bsp_vcpu);
}

/* ---- pci_emul mock implementations ----------------------------------------- */
void
pci_set_cfgdata8(struct pci_devinst *pi, int offset, uint8_t value)
{

	pi->pi_cfgdata[offset] = value;
}

void
pci_set_cfgdata16(struct pci_devinst *pi, int offset, uint16_t value)
{

	le16enc(&pi->pi_cfgdata[offset], value);
}

int
pci_emul_alloc_bar(struct pci_devinst *pi, int idx, enum pcibar_type type,
    uint64_t size)
{

	if (g_alloc_bar_fail)
		return (-1);
	pi->pi_bar[idx].type = type;
	pi->pi_bar[idx].size = size;
	return (0);
}

void
pci_lintr_request(struct pci_devinst *pi __unused)
{

	g_lintr_request_calls++;
}

void
pci_lintr_assert(struct pci_devinst *pi __unused)
{

	g_lintr_assert_calls++;
	g_lintr_state++;
}

void
pci_lintr_deassert(struct pci_devinst *pi __unused)
{

	g_lintr_deassert_calls++;
	if (g_lintr_state > 0)
		g_lintr_state--;
}

/* ---- mevent mock ----------------------------------------------------------- */
struct mevent *
mevent_add(int fd, enum ev_type type, void (*func)(int, enum ev_type, void *),
    void *param __unused)
{

	ATF_REQUIRE_EQ(EVF_TIMER, type);
	ATF_REQUIRE(func != NULL);
	g_mevent_add_calls++;
	g_last_arm_ms = fd;
	return ((struct mevent *)&g_mevent_token);
}

int
mevent_timer_update(struct mevent *evp __unused, int msecs)
{

	g_mevent_update_calls++;
	g_last_arm_ms = msecs;
	return (0);
}

int
mevent_delete(struct mevent *evp __unused)
{

	g_mevent_delete_calls++;
	return (0);
}

/* ---- config nvlist mock ---------------------------------------------------- */
struct cfg_ent {
	const char *key;
	const char *val;
};
static struct cfg_ent g_cfg[16];
static int g_cfg_n;

static void
cfg_reset(void)
{

	g_cfg_n = 0;
}

static void
cfg_set(const char *key, const char *val)
{

	g_cfg[g_cfg_n].key = key;
	g_cfg[g_cfg_n].val = val;
	g_cfg_n++;
}

const char *
get_config_value_node(const nvlist_t *nvl __unused, const char *name)
{
	int i;

	for (i = 0; i < g_cfg_n; i++)
		if (strcmp(g_cfg[i].key, name) == 0)
			return (g_cfg[i].val);
	return (NULL);
}

/* ---- snapshot wire codec mock ---------------------------------------------- */
void
vm_snapshot_buf_err(const char *name __unused, enum vm_snapshot_op op __unused)
{
}

int
vm_snapshot_buf(void *data, size_t size, struct vm_snapshot_meta *meta)
{

	if (size > meta->buffer.buf_rem)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(meta->buffer.buf, data, size);
	else
		memcpy(data, meta->buffer.buf, size);
	meta->buffer.buf += size;
	meta->buffer.buf_rem -= size;
	return (0);
}

/* ---- Device under test ----------------------------------------------------- */
#include "pci_i6300esb.c"

/* Documented oracles derived from the datasheet, not from the implementation. */
#define	ORACLE_VENDOR		0x8086
#define	ORACLE_DEVICE		0x25ab
#define	ORACLE_CLASS		0x08
#define	ORACLE_SUBCLASS		0x80
#define	ORACLE_BAR_SIZE		16
#define	ORACLE_CLOCK		0x400u		/* 1024 Hz, verified vs the
						 * in-guest Linux i6300esb driver
						 * (0x3c00 preload == 15 s/stage
						 * for a 30 s heartbeat) */
#define	ORACLE_DEFAULT_TMO	30

static void
mocks_reset(void)
{

	g_suspend_calls = 0;
	g_last_suspend_how = VM_SUSPEND_NONE;
	g_suspend_ret = 0;
	g_suspend_errno = 0;
	g_nmi_calls = 0;
	g_last_nmi_vcpu = NULL;
	g_nmi_ret = 0;
	g_vcpu_open_calls = 0;
	g_alloc_bar_fail = false;
	g_lintr_request_calls = 0;
	g_lintr_assert_calls = 0;
	g_lintr_deassert_calls = 0;
	g_lintr_state = 0;
	g_mevent_add_calls = 0;
	g_mevent_update_calls = 0;
	g_mevent_delete_calls = 0;
	g_last_arm_ms = -1;
	i6300esb_sc = NULL;
	cfg_reset();
}

static struct pci_devinst *
make_pi(void)
{
	struct pci_devinst *pi;

	pi = calloc(1, sizeof(*pi));
	ATF_REQUIRE(pi != NULL);
	pi->pi_vmctx = (struct vmctx *)(void *)pi;	/* opaque, unused */
	return (pi);
}

/* Build a standalone softc for direct entry-point drives (no init path). */
static struct i6300esb_softc *
make_sc(struct pci_devinst *pi)
{
	struct i6300esb_softc *sc;

	sc = calloc(1, sizeof(*sc));
	ATF_REQUIRE(sc != NULL);
	sc->sc_pi = pi;
	sc->sc_ctx = pi->pi_vmctx;
	sc->sc_bsp = &g_bsp_vcpu;
	pthread_mutex_init(&sc->sc_mtx, NULL);
	sc->sc_action = I6300ESB_ACT_RESET;
	sc->sc_timeout = ORACLE_DEFAULT_TMO;
	sc->sc_timer1 = ORACLE_DEFAULT_TMO * ORACLE_CLOCK;
	sc->sc_timer2 = sc->sc_timer1;
	sc->sc_stage = 1;
	pi->pi_arg = sc;
	return (sc);
}

/* Enable the watchdog exactly as a guest would: write ENABLE to LOCK. */
static void
guest_enable(struct pci_devinst *pi)
{

	ATF_REQUIRE_EQ(0, i6300esb_cfgwrite(pi, ESB_LOCK_REG, 1,
	    ESB_LOCK_ENABLE));
}

/* Pet the watchdog via the documented unlock+reload sequence. */
static void
guest_pet(struct pci_devinst *pi)
{

	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2, ESB_UNLOCK1);
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2, ESB_UNLOCK2);
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2, ESB_WDT_RELOAD);
}

/* -------------------------------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(action_parsing);
ATF_TC_BODY(action_parsing, tc)
{
	enum i6300esb_action act;

	(void)tc;
	act = I6300ESB_ACT_NMI;
	ATF_REQUIRE(i6300esb_parse_action("reset", &act));
	ATF_CHECK_EQ(I6300ESB_ACT_RESET, act);
	ATF_REQUIRE(i6300esb_parse_action("poweroff", &act));
	ATF_CHECK_EQ(I6300ESB_ACT_POWEROFF, act);
	ATF_REQUIRE(i6300esb_parse_action("nmi", &act));
	ATF_CHECK_EQ(I6300ESB_ACT_NMI, act);
	ATF_REQUIRE(i6300esb_parse_action("notify", &act));
	ATF_CHECK_EQ(I6300ESB_ACT_NOTIFY, act);

	/* Unknown / NULL are rejected and leave the output untouched. */
	act = I6300ESB_ACT_POWEROFF;
	ATF_CHECK(!i6300esb_parse_action("explode", &act));
	ATF_CHECK_EQ(I6300ESB_ACT_POWEROFF, act);
	ATF_CHECK(!i6300esb_parse_action(NULL, &act));
	ATF_CHECK(!i6300esb_parse_action("reset", NULL));

	/* Names round-trip. */
	ATF_CHECK_STREQ("reset", i6300esb_action_name(I6300ESB_ACT_RESET));
	ATF_CHECK_STREQ("poweroff", i6300esb_action_name(I6300ESB_ACT_POWEROFF));
	ATF_CHECK_STREQ("nmi", i6300esb_action_name(I6300ESB_ACT_NMI));
	ATF_CHECK_STREQ("notify", i6300esb_action_name(I6300ESB_ACT_NOTIFY));
	ATF_CHECK_STREQ("unknown", i6300esb_action_name((enum i6300esb_action)99));
}

ATF_TC_WITHOUT_HEAD(init_defaults_and_identity);
ATF_TC_BODY(init_defaults_and_identity, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();

	ATF_REQUIRE_EQ(0, i6300esb_init(pi, NULL));
	sc = pi->pi_arg;
	ATF_REQUIRE(sc != NULL);

	/* PCI identity matches the 6300ESB watchdog. */
	ATF_CHECK_EQ(ORACLE_VENDOR, le16dec(&pi->pi_cfgdata[PCIR_VENDOR]));
	ATF_CHECK_EQ(ORACLE_DEVICE, le16dec(&pi->pi_cfgdata[PCIR_DEVICE]));
	ATF_CHECK_EQ(ORACLE_CLASS, pi->pi_cfgdata[PCIR_CLASS]);
	ATF_CHECK_EQ(ORACLE_SUBCLASS, pi->pi_cfgdata[PCIR_SUBCLASS]);
	ATF_CHECK_EQ(0x1, pi->pi_cfgdata[PCIR_INTPIN]);

	/* BAR0 is the 16-byte MMIO register window and an interrupt is wired. */
	ATF_CHECK_EQ(PCIBAR_MEM32, pi->pi_bar[I6300ESB_BAR].type);
	ATF_CHECK_EQ((uint64_t)ORACLE_BAR_SIZE, pi->pi_bar[I6300ESB_BAR].size);
	ATF_CHECK_EQ(1, g_lintr_request_calls);
	ATF_CHECK_EQ(1, g_vcpu_open_calls);

	/* Defaults: action=reset, timeout=30s, both stages preloaded. */
	ATF_CHECK_EQ(I6300ESB_ACT_RESET, sc->sc_action);
	ATF_CHECK_EQ((uint32_t)ORACLE_DEFAULT_TMO, sc->sc_timeout);
	ATF_CHECK_EQ(ORACLE_DEFAULT_TMO * ORACLE_CLOCK, sc->sc_timer1);
	ATF_CHECK_EQ(ORACLE_DEFAULT_TMO * ORACLE_CLOCK, sc->sc_timer2);
	ATF_CHECK(!sc->sc_running);

	/* A second watchdog is refused. */
	ATF_CHECK_EQ(-1, i6300esb_init(make_pi(), NULL));
}

ATF_TC_WITHOUT_HEAD(init_option_parsing);
ATF_TC_BODY(init_option_parsing, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;

	/* Each action selects the matching policy and a custom timeout applies. */
	mocks_reset();
	cfg_set("action", "poweroff");
	cfg_set("timeout", "5");
	pi = make_pi();
	ATF_REQUIRE_EQ(0, i6300esb_init(pi, NULL));
	sc = pi->pi_arg;
	ATF_CHECK_EQ(I6300ESB_ACT_POWEROFF, sc->sc_action);
	ATF_CHECK_EQ(5u, sc->sc_timeout);
	ATF_CHECK_EQ(5u * ORACLE_CLOCK, sc->sc_timer1);

	mocks_reset();
	cfg_set("action", "nmi");
	pi = make_pi();
	ATF_REQUIRE_EQ(0, i6300esb_init(pi, NULL));
	ATF_CHECK_EQ(I6300ESB_ACT_NMI,
	    ((struct i6300esb_softc *)pi->pi_arg)->sc_action);

	mocks_reset();
	cfg_set("action", "notify");
	pi = make_pi();
	ATF_REQUIRE_EQ(0, i6300esb_init(pi, NULL));
	ATF_CHECK_EQ(I6300ESB_ACT_NOTIFY,
	    ((struct i6300esb_softc *)pi->pi_arg)->sc_action);

	/* Invalid action is rejected. */
	mocks_reset();
	cfg_set("action", "bogus");
	ATF_CHECK_EQ(-1, i6300esb_init(make_pi(), NULL));

	/* Invalid timeouts: zero, negative, non-numeric, above the max. */
	mocks_reset();
	cfg_set("timeout", "0");
	ATF_CHECK_EQ(-1, i6300esb_init(make_pi(), NULL));

	mocks_reset();
	cfg_set("timeout", "-3");
	ATF_CHECK_EQ(-1, i6300esb_init(make_pi(), NULL));

	mocks_reset();
	cfg_set("timeout", "abc");	/* atoi -> 0 -> rejected */
	ATF_CHECK_EQ(-1, i6300esb_init(make_pi(), NULL));

	mocks_reset();
	cfg_set("timeout", "999999");
	ATF_CHECK_EQ(-1, i6300esb_init(make_pi(), NULL));

	/* BAR allocation failure unwinds cleanly. */
	mocks_reset();
	g_alloc_bar_fail = true;
	ATF_CHECK_EQ(-1, i6300esb_init(make_pi(), NULL));
	ATF_CHECK(i6300esb_sc == NULL);
}

ATF_TC_WITHOUT_HEAD(preload_time_model);
ATF_TC_BODY(preload_time_model, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);

	/* preload / clock == seconds; 1s -> 1000ms. */
	ATF_CHECK_EQ(1000, i6300esb_preload_to_ms(sc, ORACLE_CLOCK));
	ATF_CHECK_EQ(2000, i6300esb_preload_to_ms(sc, 2 * ORACLE_CLOCK));
	/*
	 * Non-circular anchor: the real Linux i6300esb driver programs each
	 * preload stage to 0x3c00 for a 30-second heartbeat (15 s/stage, two
	 * stages).  This exact (preload, ms) pair was captured live from the
	 * in-guest driver and does not depend on ORACLE_CLOCK.
	 */
	ATF_CHECK_EQ(15000, i6300esb_preload_to_ms(sc, 0x3c00));
	/* A zero preload clamps to a single tick (>=1ms), never 0. */
	ATF_CHECK(i6300esb_preload_to_ms(sc, 0) >= 1);

	/* The CONFIG pre-scale bit doubles the interval. */
	sc->sc_config = ESB_CFG_PRE_SCALE;
	ATF_CHECK_EQ(2000, i6300esb_preload_to_ms(sc, ORACLE_CLOCK));

	/* Seconds -> preload is the datasheet clock multiple. */
	ATF_CHECK_EQ(ORACLE_CLOCK, i6300esb_timeout_to_preload(1));
	ATF_CHECK_EQ(10u * ORACLE_CLOCK, i6300esb_timeout_to_preload(10));
}

ATF_TC_WITHOUT_HEAD(bar_bounds);
ATF_TC_BODY(bar_bounds, tc)
{
	struct pci_devinst *pi;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	(void)make_sc(pi);

	/* Wrong BAR index is ignored. */
	i6300esb_barwrite(pi, 1, ESB_RELOAD_REG, 2, ESB_UNLOCK1);
	ATF_CHECK_EQ(0, i6300esb_barread(pi, 1, ESB_RELOAD_REG, 2));

	/* Out-of-window offset reads back as 0 and writes are no-ops. */
	ATF_CHECK_EQ(0, i6300esb_barread(pi, I6300ESB_BAR, ORACLE_BAR_SIZE, 2));
	i6300esb_barwrite(pi, I6300ESB_BAR, ORACLE_BAR_SIZE, 2, 0xffff);

	/* An unmapped in-window offset reads back as 0. */
	ATF_CHECK_EQ(0, i6300esb_barread(pi, I6300ESB_BAR, 0x02, 2));
	i6300esb_barwrite(pi, I6300ESB_BAR, 0x02, 2, 0x1234);
}

ATF_TC_WITHOUT_HEAD(reload_unlock_sequence);
ATF_TC_BODY(reload_unlock_sequence, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);

	/* A TIMER1 write without the unlock sequence is ignored. */
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_TIMER1_REG, 4, 0xdead);
	ATF_CHECK_EQ(sc->sc_timer1,
	    (uint32_t)i6300esb_barread(pi, I6300ESB_BAR, ESB_TIMER1_REG, 4));

	/* Unlock (0x80,0x86) then a TIMER1 write takes effect. */
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2, ESB_UNLOCK1);
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2, ESB_UNLOCK2);
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_TIMER1_REG, 4, 4u * ORACLE_CLOCK);
	ATF_CHECK_EQ(4u * ORACLE_CLOCK,
	    (uint32_t)i6300esb_barread(pi, I6300ESB_BAR, ESB_TIMER1_REG, 4));

	/* The unlock is single-shot: a second TIMER1 write is ignored again. */
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_TIMER1_REG, 4, 0x1111);
	ATF_CHECK_EQ(4u * ORACLE_CLOCK,
	    (uint32_t)i6300esb_barread(pi, I6300ESB_BAR, ESB_TIMER1_REG, 4));

	/* TIMER2 likewise requires an unlock. */
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_TIMER2_REG, 4, 0x2222);
	ATF_CHECK_EQ(sc->sc_timer2,
	    (uint32_t)i6300esb_barread(pi, I6300ESB_BAR, ESB_TIMER2_REG, 4));
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2, ESB_UNLOCK1);
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2, ESB_UNLOCK2);
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_TIMER2_REG, 4, 7u * ORACLE_CLOCK);
	ATF_CHECK_EQ(7u * ORACLE_CLOCK,
	    (uint32_t)i6300esb_barread(pi, I6300ESB_BAR, ESB_TIMER2_REG, 4));

	/* 0x86 without a preceding 0x80 does not unlock. */
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2, ESB_UNLOCK2);
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_TIMER1_REG, 4, 0x3333);
	ATF_CHECK_EQ(4u * ORACLE_CLOCK,
	    (uint32_t)i6300esb_barread(pi, I6300ESB_BAR, ESB_TIMER1_REG, 4));

	/* A reload command while stopped does not arm the timer. */
	guest_pet(pi);
	ATF_CHECK_EQ(0, g_mevent_add_calls);
	ATF_CHECK_EQ(0, g_mevent_update_calls);
}

ATF_TC_WITHOUT_HEAD(config_register_and_lock);
ATF_TC_BODY(config_register_and_lock, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;
	uint32_t rv;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);

	/* CONFIG write stores only the defined bits; read them back. */
	ATF_REQUIRE_EQ(0, i6300esb_cfgwrite(pi, ESB_CONFIG_REG, 2,
	    ESB_CFG_INTTYPE | ESB_CFG_OUTPUT | 0xff00));
	rv = 0;
	ATF_REQUIRE_EQ(0, i6300esb_cfgread(pi, ESB_CONFIG_REG, 2, &rv));
	ATF_CHECK_EQ((uint32_t)(ESB_CFG_INTTYPE | ESB_CFG_OUTPUT), rv);

	/* Unrelated config offsets/sizes fall through to default handling. */
	ATF_CHECK_EQ(-1, i6300esb_cfgwrite(pi, 0x10, 4, 0x1234));
	rv = 0;
	ATF_CHECK_EQ(1, i6300esb_cfgread(pi, 0x10, 4, &rv));

	/* Set the LOCK bit; the configuration is now immutable. */
	ATF_REQUIRE_EQ(0, i6300esb_cfgwrite(pi, ESB_LOCK_REG, 1,
	    ESB_LOCK_LOCKED));
	ATF_REQUIRE_EQ(0, i6300esb_cfgwrite(pi, ESB_CONFIG_REG, 2, 0x0));
	rv = 0;
	ATF_REQUIRE_EQ(0, i6300esb_cfgread(pi, ESB_CONFIG_REG, 2, &rv));
	ATF_CHECK_EQ((uint32_t)(ESB_CFG_INTTYPE | ESB_CFG_OUTPUT), rv);

	/* LOCK is sticky: it cannot be cleared once set. */
	ATF_REQUIRE_EQ(0, i6300esb_cfgwrite(pi, ESB_LOCK_REG, 1, 0x0));
	rv = 0;
	ATF_REQUIRE_EQ(0, i6300esb_cfgread(pi, ESB_LOCK_REG, 1, &rv));
	ATF_CHECK((rv & ESB_LOCK_LOCKED) != 0);
	(void)sc;
}

ATF_TC_WITHOUT_HEAD(enable_disable_lifecycle);
ATF_TC_BODY(enable_disable_lifecycle, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);

	/* Enabling arms the stage-1 timer at the programmed interval. */
	guest_enable(pi);
	ATF_CHECK(sc->sc_running);
	ATF_CHECK_EQ(1, sc->sc_stage);
	ATF_CHECK_EQ(1, g_mevent_add_calls);
	ATF_CHECK_EQ(ORACLE_DEFAULT_TMO * 1000, g_last_arm_ms);

	/* Disabling (ENABLE cleared while unlocked) stops and disarms it. */
	ATF_REQUIRE_EQ(0, i6300esb_cfgwrite(pi, ESB_LOCK_REG, 1, 0x0));
	ATF_CHECK(!sc->sc_running);
	ATF_CHECK_EQ(1, g_mevent_delete_calls);

	/* Once locked+enabled, ENABLE is sticky and cannot be cleared. */
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	ATF_REQUIRE_EQ(0, i6300esb_cfgwrite(pi, ESB_LOCK_REG, 1,
	    ESB_LOCK_ENABLE | ESB_LOCK_LOCKED));
	ATF_CHECK(sc->sc_running);
	ATF_REQUIRE_EQ(0, i6300esb_cfgwrite(pi, ESB_LOCK_REG, 1, 0x0));
	ATF_CHECK(sc->sc_running);
}

ATF_TC_WITHOUT_HEAD(pet_keeps_alive);
ATF_TC_BODY(pet_keeps_alive, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	guest_enable(pi);

	/* Stage-1 expiry raises the interrupt and advances to stage 2. */
	i6300esb_expire(sc);
	ATF_CHECK_EQ(2, sc->sc_stage);
	ATF_CHECK((sc->sc_gintsts & ESB_GINTSTS_TIMEOUT) != 0);
	ATF_CHECK_EQ(1, g_lintr_assert_calls);
	/* The interrupt status is observable through a GINTSTS read. */
	ATF_CHECK((i6300esb_barread(pi, I6300ESB_BAR, ESB_GINTSTS_REG, 2) &
	    ESB_GINTSTS_TIMEOUT) != 0);
	/* RELOAD register now reports the timeout to the guest. */
	ATF_CHECK((i6300esb_barread(pi, I6300ESB_BAR, ESB_RELOAD_REG, 2) &
	    ESB_WDT_TIMEOUT) != 0);

	/* Petting before stage-2 returns to stage 1 and clears the interrupt. */
	guest_pet(pi);
	ATF_CHECK_EQ(1, sc->sc_stage);
	ATF_CHECK((sc->sc_gintsts & ESB_GINTSTS_TIMEOUT) == 0);
	ATF_CHECK_EQ(0, g_lintr_state);
	ATF_CHECK_EQ(0, g_suspend_calls);

	/* The watchdog stays alive across repeated stage-1/pet cycles. */
	i6300esb_expire(sc);
	ATF_CHECK_EQ(2, sc->sc_stage);
	guest_pet(pi);
	ATF_CHECK_EQ(1, sc->sc_stage);
	ATF_CHECK_EQ(0, g_suspend_calls);
	ATF_CHECK_EQ(0, g_nmi_calls);

	/* GINTSTS is write-1-to-clear and deasserts the interrupt. */
	i6300esb_expire(sc);
	ATF_CHECK((sc->sc_gintsts & ESB_GINTSTS_TIMEOUT) != 0);
	i6300esb_barwrite(pi, I6300ESB_BAR, ESB_GINTSTS_REG, 2,
	    ESB_GINTSTS_TIMEOUT);
	ATF_CHECK((sc->sc_gintsts & ESB_GINTSTS_TIMEOUT) == 0);
	ATF_CHECK_EQ(0, g_lintr_state);
}

ATF_TC_WITHOUT_HEAD(stage1_interrupt_types);
ATF_TC_BODY(stage1_interrupt_types, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	/* INTTYPE=disabled: stage-1 sets status but raises no interrupt. */
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_config = ESB_INTTYPE_DISABLED;	/* bits 1:0 = 11b */
	guest_enable(pi);
	i6300esb_expire(sc);
	ATF_CHECK((sc->sc_gintsts & ESB_GINTSTS_TIMEOUT) != 0);
	ATF_CHECK_EQ(0, g_lintr_assert_calls);

	/* INTTYPE=IRQ: stage-1 asserts the PCI interrupt. */
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_config = ESB_INTTYPE_IRQ;
	guest_enable(pi);
	i6300esb_expire(sc);
	ATF_CHECK_EQ(1, g_lintr_assert_calls);
}

ATF_TC_WITHOUT_HEAD(stage2_action_reset);
ATF_TC_BODY(stage2_action_reset, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_action = I6300ESB_ACT_RESET;
	guest_enable(pi);

	i6300esb_expire(sc);	/* stage 1 */
	i6300esb_expire(sc);	/* stage 2 -> action */
	ATF_CHECK_EQ(1, g_suspend_calls);
	ATF_CHECK_EQ(VM_SUSPEND_RESET, g_last_suspend_how);
	ATF_CHECK(!sc->sc_running);

	/* A stopped watchdog ignores further expiries. */
	i6300esb_expire(sc);
	ATF_CHECK_EQ(1, g_suspend_calls);

	/* An EALREADY from vm_suspend is tolerated (idempotent shutdown). */
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	guest_enable(pi);
	g_suspend_ret = -1;
	g_suspend_errno = EALREADY;
	i6300esb_expire(sc);
	i6300esb_expire(sc);
	ATF_CHECK_EQ(1, g_suspend_calls);
}

ATF_TC_WITHOUT_HEAD(stage2_action_poweroff);
ATF_TC_BODY(stage2_action_poweroff, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_action = I6300ESB_ACT_POWEROFF;
	guest_enable(pi);
	i6300esb_expire(sc);
	i6300esb_expire(sc);
	ATF_CHECK_EQ(1, g_suspend_calls);
	ATF_CHECK_EQ(VM_SUSPEND_POWEROFF, g_last_suspend_how);

	/* A non-EALREADY vm_suspend error is reported but still stops. */
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_action = I6300ESB_ACT_POWEROFF;
	guest_enable(pi);
	g_suspend_ret = -1;
	g_suspend_errno = EPERM;
	i6300esb_expire(sc);
	i6300esb_expire(sc);
	ATF_CHECK_EQ(1, g_suspend_calls);
	ATF_CHECK(!sc->sc_running);
}

ATF_TC_WITHOUT_HEAD(stage2_action_nmi);
ATF_TC_BODY(stage2_action_nmi, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_action = I6300ESB_ACT_NMI;
	guest_enable(pi);

	i6300esb_expire(sc);	/* stage 1 */
	i6300esb_expire(sc);	/* stage 2 -> NMI */
	ATF_CHECK_EQ(1, g_nmi_calls);
	ATF_CHECK(g_last_nmi_vcpu == &g_bsp_vcpu);
	ATF_CHECK_EQ(0, g_suspend_calls);
	/* NMI is a prod: the watchdog keeps running, back at stage 1. */
	ATF_CHECK(sc->sc_running);
	ATF_CHECK_EQ(1, sc->sc_stage);

	/* A failing vm_inject_nmi is reported but still reloads. */
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_action = I6300ESB_ACT_NMI;
	guest_enable(pi);
	g_nmi_ret = -1;
	i6300esb_expire(sc);
	i6300esb_expire(sc);
	ATF_CHECK_EQ(1, g_nmi_calls);
	ATF_CHECK(sc->sc_running);
}

ATF_TC_WITHOUT_HEAD(stage2_action_notify);
ATF_TC_BODY(stage2_action_notify, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_action = I6300ESB_ACT_NOTIFY;
	guest_enable(pi);

	i6300esb_expire(sc);	/* stage 1 */
	i6300esb_expire(sc);	/* stage 2 -> notify only */
	ATF_CHECK_EQ(0, g_suspend_calls);
	ATF_CHECK_EQ(0, g_nmi_calls);
	/* Notify leaves the guest running but stops the watchdog. */
	ATF_CHECK(!sc->sc_running);
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_save_restore);
ATF_TC_BODY(snapshot_save_restore, tc)
{
	struct pci_devinst *pi_save, *pi_restore;
	struct i6300esb_softc *sc_save, *sc_restore;
	uint8_t buf[64];
	size_t used;

	(void)tc;
	mocks_reset();
	pi_save = make_pi();
	sc_save = make_sc(pi_save);
	pi_restore = make_pi();
	sc_restore = make_sc(pi_restore);

	/* Seed distinctive state on the source. */
	sc_save->sc_action = I6300ESB_ACT_NMI;
	sc_save->sc_running = true;
	sc_save->sc_stage = 2;
	sc_save->sc_timeout_flag = true;
	sc_save->sc_lock = ESB_LOCK_ENABLE | ESB_LOCK_LOCKED;
	sc_save->sc_config = ESB_CFG_INTTYPE | ESB_CFG_OUTPUT;
	sc_save->sc_gintsts = ESB_GINTSTS_TIMEOUT;
	sc_save->sc_timer1 = 3u * ORACLE_CLOCK;
	sc_save->sc_timer2 = 9u * ORACLE_CLOCK;
	sc_save->sc_timeout = 3;

	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi_save,
			.op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = sizeof(buf),
			    .buf_start = buf, .buf_size = sizeof(buf) },
		};
		ATF_REQUIRE_EQ(0, i6300esb_snapshot(&meta));
		used = sizeof(buf) - meta.buffer.buf_rem;
	}

	/* Restore into the second instance; stage-2 timer is re-armed. */
	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi_restore,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_REQUIRE_EQ(0, i6300esb_snapshot(&meta));
	}
	ATF_CHECK_EQ(I6300ESB_ACT_NMI, sc_restore->sc_action);
	ATF_CHECK(sc_restore->sc_running);
	ATF_CHECK_EQ(2, sc_restore->sc_stage);
	ATF_CHECK(sc_restore->sc_timeout_flag);
	ATF_CHECK_EQ(ESB_LOCK_ENABLE | ESB_LOCK_LOCKED, sc_restore->sc_lock);
	ATF_CHECK_EQ((uint16_t)(ESB_CFG_INTTYPE | ESB_CFG_OUTPUT),
	    sc_restore->sc_config);
	ATF_CHECK_EQ(ESB_GINTSTS_TIMEOUT, sc_restore->sc_gintsts);
	ATF_CHECK_EQ(3u * ORACLE_CLOCK, sc_restore->sc_timer1);
	ATF_CHECK_EQ(9u * ORACLE_CLOCK, sc_restore->sc_timer2);
	ATF_CHECK_EQ(3u, sc_restore->sc_timeout);
	/* Running at stage 2 -> the stage-2 interval was re-armed on restore. */
	ATF_CHECK_EQ(1, g_mevent_add_calls);
	ATF_CHECK_EQ(9 * 1000, g_last_arm_ms);
}

ATF_TC_WITHOUT_HEAD(snapshot_restore_stopped_disarms);
ATF_TC_BODY(snapshot_restore_stopped_disarms, tc)
{
	struct pci_devinst *pi_save, *pi_restore;
	struct i6300esb_softc *sc_save, *sc_restore;
	uint8_t buf[64];
	size_t used;

	(void)tc;
	mocks_reset();
	pi_save = make_pi();
	sc_save = make_sc(pi_save);
	pi_restore = make_pi();
	sc_restore = make_sc(pi_restore);

	sc_save->sc_running = false;
	sc_save->sc_stage = 1;

	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi_save,
			.op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = sizeof(buf),
			    .buf_start = buf, .buf_size = sizeof(buf) },
		};
		ATF_REQUIRE_EQ(0, i6300esb_snapshot(&meta));
		used = sizeof(buf) - meta.buffer.buf_rem;
	}
	/* Pretend the destination had a stale armed timer. */
	sc_restore->sc_timer = (struct mevent *)&g_mevent_token;
	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi_restore,
			.op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_REQUIRE_EQ(0, i6300esb_snapshot(&meta));
	}
	ATF_CHECK(!sc_restore->sc_running);
	ATF_CHECK_EQ(1, g_mevent_delete_calls);
	ATF_CHECK(sc_restore->sc_timer == NULL);
}

/*
 * A checkpoint image with an out-of-range action byte (only version and stage
 * are validated on decode) must still be handled safely: on a stage-2 expiry
 * the action switch falls to its default, which stops the watchdog without
 * invoking any host lifecycle action.  This exercises the hostile-restore path.
 */
ATF_TC_WITHOUT_HEAD(snapshot_restore_bad_action_is_safe);
ATF_TC_BODY(snapshot_restore_bad_action_is_safe, tc)
{
	struct pci_devinst *pi_save, *pi_restore;
	struct i6300esb_softc *sc_save, *sc_restore;
	uint8_t buf[64];
	size_t used;

	(void)tc;
	mocks_reset();
	pi_save = make_pi();
	sc_save = make_sc(pi_save);
	pi_restore = make_pi();
	sc_restore = make_sc(pi_restore);

	sc_save->sc_running = true;
	sc_save->sc_stage = 2;

	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi_save, .op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = sizeof(buf),
			    .buf_start = buf, .buf_size = sizeof(buf) },
		};
		ATF_REQUIRE_EQ(0, i6300esb_snapshot(&meta));
		used = sizeof(buf) - meta.buffer.buf_rem;
	}

	/* Corrupt the action byte to a value outside the defined enum range. */
	buf[1] = 0x7f;
	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi_restore, .op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_REQUIRE_EQ(0, i6300esb_snapshot(&meta));
	}
	ATF_CHECK(sc_restore->sc_running);
	ATF_CHECK_EQ(2, sc_restore->sc_stage);
	ATF_CHECK_EQ(1, g_mevent_add_calls);

	/* Stage-2 expiry with the bogus action stops the watchdog, nothing else. */
	i6300esb_expire(sc_restore);
	ATF_CHECK_EQ(0, g_suspend_calls);
	ATF_CHECK_EQ(0, g_nmi_calls);
	ATF_CHECK(!sc_restore->sc_running);
	ATF_CHECK_EQ(1, g_mevent_delete_calls);
}

ATF_TC_WITHOUT_HEAD(snapshot_guards_and_corruption);
ATF_TC_BODY(snapshot_guards_and_corruption, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;
	uint8_t buf[64];
	size_t used;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_running = true;
	sc->sc_stage = 1;

	/* NULL meta / NULL dev_data / missing softc are all rejected. */
	ATF_CHECK_EQ(EINVAL, i6300esb_snapshot(NULL));
	{
		struct vm_snapshot_meta meta = {
			.dev_data = NULL, .op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = sizeof(buf),
			    .buf_start = buf, .buf_size = sizeof(buf) },
		};
		ATF_CHECK_EQ(EINVAL, i6300esb_snapshot(&meta));
	}
	{
		struct pci_devinst pi2 = { .pi_arg = NULL };
		struct vm_snapshot_meta meta = {
			.dev_data = &pi2, .op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = sizeof(buf),
			    .buf_start = buf, .buf_size = sizeof(buf) },
		};
		ATF_CHECK_EQ(EINVAL, i6300esb_snapshot(&meta));
	}

	/* Produce a good image. */
	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi, .op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = sizeof(buf),
			    .buf_start = buf, .buf_size = sizeof(buf) },
		};
		ATF_REQUIRE_EQ(0, i6300esb_snapshot(&meta));
		used = sizeof(buf) - meta.buffer.buf_rem;
	}

	/* A bad version byte is rejected. */
	buf[0] ^= 0xff;
	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi, .op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK_EQ(EINVAL, i6300esb_snapshot(&meta));
	}
	buf[0] ^= 0xff;

	/* A bad stage value is rejected. */
	buf[3] = 5;
	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi, .op = VM_SNAPSHOT_RESTORE,
			.buffer = { .buf = buf, .buf_rem = used,
			    .buf_start = buf, .buf_size = used },
		};
		ATF_CHECK_EQ(EINVAL, i6300esb_snapshot(&meta));
	}

	/* A short buffer surfaces the codec error through the goto. */
	{
		struct vm_snapshot_meta meta = {
			.dev_data = pi, .op = VM_SNAPSHOT_SAVE,
			.buffer = { .buf = buf, .buf_rem = 4,
			    .buf_start = buf, .buf_size = 4 },
		};
		ATF_CHECK(i6300esb_snapshot(&meta) != 0);
	}
}
#endif /* BHYVE_SNAPSHOT */

ATF_TC_WITHOUT_HEAD(timer_callback_dispatches);
ATF_TC_BODY(timer_callback_dispatches, tc)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;

	(void)tc;
	mocks_reset();
	pi = make_pi();
	sc = make_sc(pi);
	sc->sc_action = I6300ESB_ACT_RESET;
	guest_enable(pi);

	/* The mevent callback drives the same stage machine under the lock. */
	i6300esb_timer_cb(0, EVF_TIMER, sc);	/* stage 1 */
	ATF_CHECK_EQ(2, sc->sc_stage);
	i6300esb_timer_cb(0, EVF_TIMER, sc);	/* stage 2 -> reset */
	ATF_CHECK_EQ(1, g_suspend_calls);
	ATF_CHECK_EQ(VM_SUSPEND_RESET, g_last_suspend_how);
}

ATF_TC_WITHOUT_HEAD(devemu_registration);
ATF_TC_BODY(devemu_registration, tc)
{

	ATF_CHECK_STREQ("i6300esb", pci_de_i6300esb.pe_emu);
	ATF_CHECK(pci_de_i6300esb.pe_init == i6300esb_init);
	ATF_CHECK(pci_de_i6300esb.pe_barwrite == i6300esb_barwrite);
	ATF_CHECK(pci_de_i6300esb.pe_barread == i6300esb_barread);
	ATF_CHECK(pci_de_i6300esb.pe_cfgwrite == i6300esb_cfgwrite);
	ATF_CHECK(pci_de_i6300esb.pe_cfgread == i6300esb_cfgread);
#ifdef BHYVE_SNAPSHOT
	ATF_CHECK(pci_de_i6300esb.pe_snapshot == i6300esb_snapshot);
#endif
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, action_parsing);
	ATF_TP_ADD_TC(tp, init_defaults_and_identity);
	ATF_TP_ADD_TC(tp, init_option_parsing);
	ATF_TP_ADD_TC(tp, preload_time_model);
	ATF_TP_ADD_TC(tp, bar_bounds);
	ATF_TP_ADD_TC(tp, reload_unlock_sequence);
	ATF_TP_ADD_TC(tp, config_register_and_lock);
	ATF_TP_ADD_TC(tp, enable_disable_lifecycle);
	ATF_TP_ADD_TC(tp, pet_keeps_alive);
	ATF_TP_ADD_TC(tp, stage1_interrupt_types);
	ATF_TP_ADD_TC(tp, stage2_action_reset);
	ATF_TP_ADD_TC(tp, stage2_action_poweroff);
	ATF_TP_ADD_TC(tp, stage2_action_nmi);
	ATF_TP_ADD_TC(tp, stage2_action_notify);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp, snapshot_save_restore);
	ATF_TP_ADD_TC(tp, snapshot_restore_stopped_disarms);
	ATF_TP_ADD_TC(tp, snapshot_restore_bad_action_is_safe);
	ATF_TP_ADD_TC(tp, snapshot_guards_and_corruption);
#endif
	ATF_TP_ADD_TC(tp, timer_callback_dispatches);
	ATF_TP_ADD_TC(tp, devemu_registration);
	return (atf_no_error());
}
