/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Emulation of the Intel 6300ESB PCI-to-PCI bridge watchdog timer (the
 * "i6300esb" device that stock guest drivers -- Linux i6300esb, the Windows
 * Intel watchdog driver -- already bind to).
 *
 * The device presents a single small MMIO BAR holding the two-stage timer
 * registers (TIMER1/TIMER2 preload, the general interrupt status register and
 * the RELOAD register) plus two PCI-config-space registers (CONFIG and LOCK).
 * The guest arms the watchdog by setting WDT_ENABLE in the LOCK register and
 * keeps it alive ("pets" it) by writing the unlock sequence 0x80, 0x86 to the
 * RELOAD register followed by a write with the RELOAD bit set.  If the guest
 * stops petting, the first stage expires -- raising an interrupt per the
 * CONFIG interrupt type -- and, if still not petted, the second stage expires
 * and the host applies the operator-selected action (reset/poweroff/nmi/
 * notify) using bhyve's existing lifecycle machinery.
 *
 *  -s <slot>,i6300esb,action=reset|poweroff|nmi|notify,timeout=<seconds>
 *
 * This is an independent, datasheet-driven implementation.  It follows the
 * Intel 6300ESB datasheet register semantics and the behavioral contract that
 * guest drivers observe; no code is derived from any other emulator.
 */

#include <sys/types.h>
#include <sys/endian.h>

#include <machine/vmm.h>
#ifdef BHYVE_SNAPSHOT
#include <machine/vmm_snapshot.h>
#endif

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dev/pci/pcireg.h>

#include <vmmapi.h>

#include "config.h"
#include "debug.h"
#include "mevent.h"
#include "pci_emul.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif

#define	I6300ESB_VENDOR		0x8086
#define	I6300ESB_DEVICE		0x25ab
/* Base class 0x08 (base system peripheral), subclass 0x80 (other). */
#define	I6300ESB_CLASS		0x08
#define	I6300ESB_SUBCLASS	0x80

/* MMIO BAR0 register window (relocatable memory-mapped registers). */
#define	I6300ESB_BAR		0
#define	I6300ESB_BAR_SIZE	16

#define	ESB_TIMER1_REG		0x00	/* Stage-1 preload value (32-bit) */
#define	ESB_TIMER2_REG		0x04	/* Stage-2 preload value (32-bit) */
#define	ESB_GINTSTS_REG		0x08	/* General interrupt status (16-bit) */
#define	ESB_RELOAD_REG		0x0c	/* Reload / unlock register (16-bit) */

/* RELOAD register bits and the unlock magic values. */
#define	ESB_WDT_RELOAD		0x0100	/* Write to reload the counter */
#define	ESB_WDT_TIMEOUT		0x0200	/* Stage-1 timeout occurred (read) */
#define	ESB_UNLOCK1		0x80
#define	ESB_UNLOCK2		0x86

/* GINTSTS bits. */
#define	ESB_GINTSTS_TIMEOUT	0x0001	/* Stage-1 interrupt pending (W1C) */

/* CONFIG register (PCI config space, 16-bit). */
#define	ESB_CONFIG_REG		0x60
#define	ESB_CFG_INTTYPE		0x0003	/* 0=IRQ 1=rsvd 2=SMI 3=disabled */
#define	ESB_CFG_PRE_SCALE	0x0004	/* Pre-timeout clock scaling */
#define	ESB_CFG_OUTPUT		0x0020	/* Output/reboot enable */
#define	ESB_CFG_MASK		(ESB_CFG_INTTYPE | ESB_CFG_PRE_SCALE | \
				 ESB_CFG_OUTPUT)
#define	ESB_INTTYPE_IRQ		0
#define	ESB_INTTYPE_DISABLED	3

/* LOCK register (PCI config space, 8-bit). */
#define	ESB_LOCK_REG		0x68
#define	ESB_LOCK_LOCKED		0x01	/* Configuration locked (nowayout) */
#define	ESB_LOCK_ENABLE		0x02	/* WDT enable */
#define	ESB_LOCK_MASK		(ESB_LOCK_LOCKED | ESB_LOCK_ENABLE)

/*
 * Modeled decrement clock.  Verified against the in-guest Linux i6300esb
 * driver: for a 30-second heartbeat it programs both preload stages to
 * 0x3c00 (15360), i.e. 15 s per stage at 1024 Hz, with the reset falling at
 * stage1 + stage2 == 30 s.  The counter therefore ticks at 1024 Hz (this
 * matches the FreeBSD ichwd/i6300esbwd driver's 1<<10 ticks/second too).
 * An earlier 131072 Hz guess fired ~128x too fast.
 */
#define	ESB_CLOCK_HZ		0x400u		/* 1024 Hz */
/* Pre-scale halves the effective decrement rate (doubles the interval). */
#define	ESB_PRESCALE_SHIFT	1

#define	I6300ESB_DEFAULT_TIMEOUT	30	/* seconds, per operator default */
#define	I6300ESB_MAX_TIMEOUT		2046	/* 20-bit preload / clock */

#define	I6300ESB_NAME		"i6300esb"

enum i6300esb_action {
	I6300ESB_ACT_RESET = 0,
	I6300ESB_ACT_POWEROFF,
	I6300ESB_ACT_NMI,
	I6300ESB_ACT_NOTIFY,
};

struct i6300esb_softc {
	struct pci_devinst	*sc_pi;
	struct vmctx		*sc_ctx;
	struct vcpu		*sc_bsp;	/* NMI target (BSP) */
	pthread_mutex_t		sc_mtx;
	struct mevent		*sc_timer;

	enum i6300esb_action	sc_action;
	uint32_t		sc_timeout;	/* operator default, seconds */

	/* Register state. */
	uint32_t		sc_timer1;	/* stage-1 preload */
	uint32_t		sc_timer2;	/* stage-2 preload */
	uint16_t		sc_config;	/* CONFIG register */
	uint8_t			sc_lock;	/* LOCK register */
	uint16_t		sc_gintsts;	/* general interrupt status */

	/* Live watchdog state. */
	bool			sc_running;	/* armed and counting */
	uint8_t			sc_stage;	/* 1 or 2 */
	bool			sc_timeout_flag;/* stage-1 has fired */
	uint8_t			sc_unlock;	/* 0, 1 (saw 0x80), 2 (unlocked) */
};

static struct i6300esb_softc *i6300esb_sc;

/* ---- action helpers -------------------------------------------------------- */

static const char *
i6300esb_action_name(enum i6300esb_action act)
{

	switch (act) {
	case I6300ESB_ACT_RESET:
		return ("reset");
	case I6300ESB_ACT_POWEROFF:
		return ("poweroff");
	case I6300ESB_ACT_NMI:
		return ("nmi");
	case I6300ESB_ACT_NOTIFY:
		return ("notify");
	}
	return ("unknown");
}

static bool
i6300esb_parse_action(const char *val, enum i6300esb_action *out)
{

	if (val == NULL || out == NULL)
		return (false);
	if (strcmp(val, "reset") == 0)
		*out = I6300ESB_ACT_RESET;
	else if (strcmp(val, "poweroff") == 0)
		*out = I6300ESB_ACT_POWEROFF;
	else if (strcmp(val, "nmi") == 0)
		*out = I6300ESB_ACT_NMI;
	else if (strcmp(val, "notify") == 0)
		*out = I6300ESB_ACT_NOTIFY;
	else
		return (false);
	return (true);
}

/* ---- timing model ---------------------------------------------------------- */

static int
i6300esb_preload_to_ms(const struct i6300esb_softc *sc, uint32_t preload)
{
	uint64_t ticks, ms;

	/* A zero preload would busy-loop the timer; clamp to one tick. */
	ticks = preload != 0 ? preload : 1;
	if ((sc->sc_config & ESB_CFG_PRE_SCALE) != 0)
		ticks <<= ESB_PRESCALE_SHIFT;
	ms = (ticks * 1000u) / ESB_CLOCK_HZ;
	if (ms == 0)
		ms = 1;
	if (ms > INT32_MAX)
		ms = INT32_MAX;
	return ((int)ms);
}

static uint32_t
i6300esb_timeout_to_preload(uint32_t seconds)
{

	return (seconds * ESB_CLOCK_HZ);
}

/* ---- timer plumbing (thin wrappers over mevent) ---------------------------- */

static void i6300esb_timer_cb(int fd, enum ev_type type, void *arg);

/*
 * (Re)arm the host timer for the given interval.  Kept behind a single helper
 * so the stage machine never touches mevent directly.
 */
static void
i6300esb_arm(struct i6300esb_softc *sc, int ms)
{

	if (sc->sc_timer != NULL) {
		(void)mevent_timer_update(sc->sc_timer, ms);
		return;
	}
	sc->sc_timer = mevent_add(ms, EVF_TIMER, i6300esb_timer_cb, sc);
}

static void
i6300esb_disarm(struct i6300esb_softc *sc)
{

	if (sc->sc_timer != NULL) {
		(void)mevent_delete(sc->sc_timer);
		sc->sc_timer = NULL;
	}
}

/* ---- stage machine --------------------------------------------------------- */

/*
 * Reload ("pet") the watchdog: return to stage 1, clear the stage-1 timeout
 * indication and interrupt, and restart the stage-1 interval.
 */
static void
i6300esb_reload(struct i6300esb_softc *sc)
{

	sc->sc_stage = 1;
	sc->sc_timeout_flag = false;
	sc->sc_gintsts &= ~ESB_GINTSTS_TIMEOUT;
	pci_lintr_deassert(sc->sc_pi);
	i6300esb_arm(sc, i6300esb_preload_to_ms(sc, sc->sc_timer1));
}

static void
i6300esb_start(struct i6300esb_softc *sc)
{

	sc->sc_running = true;
	i6300esb_reload(sc);
}

static void
i6300esb_stop(struct i6300esb_softc *sc)
{

	sc->sc_running = false;
	i6300esb_disarm(sc);
	pci_lintr_deassert(sc->sc_pi);
}

/* Deliver the stage-1 interrupt according to the CONFIG interrupt type. */
static void
i6300esb_stage1_interrupt(struct i6300esb_softc *sc)
{
	unsigned int inttype;

	sc->sc_timeout_flag = true;
	sc->sc_gintsts |= ESB_GINTSTS_TIMEOUT;

	inttype = sc->sc_config & ESB_CFG_INTTYPE;
	if (inttype == ESB_INTTYPE_DISABLED)
		return;
	/* IRQ and SMI both surface as the device's PCI interrupt here. */
	pci_lintr_assert(sc->sc_pi);
}

/* Apply the operator-selected host action on stage-2 expiry. */
static void
i6300esb_fire_action(struct i6300esb_softc *sc)
{
	enum vm_suspend_how how;
	int error;

	EPRINTLN("%s: watchdog expired, applying action \"%s\"", I6300ESB_NAME,
	    i6300esb_action_name(sc->sc_action));

	switch (sc->sc_action) {
	case I6300ESB_ACT_RESET:
		how = VM_SUSPEND_RESET;
		break;
	case I6300ESB_ACT_POWEROFF:
		how = VM_SUSPEND_POWEROFF;
		break;
	case I6300ESB_ACT_NMI:
		error = vm_inject_nmi(sc->sc_bsp);
		if (error != 0)
			EPRINTLN("%s: vm_inject_nmi failed: %s", I6300ESB_NAME,
			    strerror(errno));
		/* An NMI is a prod, not a lifecycle change: keep counting. */
		i6300esb_reload(sc);
		return;
	case I6300ESB_ACT_NOTIFY:
		/* Notify-only: leave the guest running, stop the watchdog. */
		i6300esb_stop(sc);
		return;
	default:
		i6300esb_stop(sc);
		return;
	}

	error = vm_suspend(sc->sc_ctx, how);
	if (error != 0 && errno != EALREADY)
		EPRINTLN("%s: vm_suspend failed: %s", I6300ESB_NAME,
		    strerror(errno));
	i6300esb_stop(sc);
}

/*
 * One timer interval elapsed.  Stage 1 raises the interrupt and advances to
 * stage 2; stage 2 applies the host action.  Pure with respect to mevent so it
 * can be driven directly by tests.
 */
static void
i6300esb_expire(struct i6300esb_softc *sc)
{

	if (!sc->sc_running)
		return;

	if (sc->sc_stage == 1) {
		i6300esb_stage1_interrupt(sc);
		sc->sc_stage = 2;
		i6300esb_arm(sc, i6300esb_preload_to_ms(sc, sc->sc_timer2));
	} else {
		i6300esb_fire_action(sc);
	}
}

static void
i6300esb_timer_cb(int fd __unused, enum ev_type type __unused, void *arg)
{
	struct i6300esb_softc *sc = arg;

	pthread_mutex_lock(&sc->sc_mtx);
	i6300esb_expire(sc);
	pthread_mutex_unlock(&sc->sc_mtx);
}

/* ---- MMIO register access -------------------------------------------------- */

/*
 * Handle a write to the RELOAD register: the unlock state machine and the
 * reload ("pet") command.  Writing 0x80 then 0x86 unlocks the next write to a
 * memory-mapped register; a write with the RELOAD bit set while unlocked pets
 * the watchdog.
 */
static void
i6300esb_reload_write(struct i6300esb_softc *sc, uint16_t value)
{

	if (value == ESB_UNLOCK1) {
		sc->sc_unlock = 1;
		return;
	}
	if (value == ESB_UNLOCK2 && sc->sc_unlock == 1) {
		sc->sc_unlock = 2;
		return;
	}

	/* Any other write consumes (and clears) the unlock window. */
	if (sc->sc_unlock == 2 && (value & ESB_WDT_RELOAD) != 0) {
		if (sc->sc_running)
			i6300esb_reload(sc);
	}
	sc->sc_unlock = 0;
}

static void
i6300esb_mmio_write(struct i6300esb_softc *sc, uint64_t offset, int size,
    uint64_t value)
{
	bool unlocked;

	/* TIMER1/TIMER2 writes require the immediately preceding unlock. */
	unlocked = (sc->sc_unlock == 2);

	switch (offset) {
	case ESB_TIMER1_REG:
		if (unlocked) {
			sc->sc_timer1 = (uint32_t)value;
			sc->sc_unlock = 0;
		}
		break;
	case ESB_TIMER2_REG:
		if (unlocked) {
			sc->sc_timer2 = (uint32_t)value;
			sc->sc_unlock = 0;
		}
		break;
	case ESB_GINTSTS_REG:
		/* Write-1-to-clear the stage-1 interrupt status. */
		if ((value & ESB_GINTSTS_TIMEOUT) != 0) {
			sc->sc_gintsts &= ~ESB_GINTSTS_TIMEOUT;
			pci_lintr_deassert(sc->sc_pi);
		}
		break;
	case ESB_RELOAD_REG:
		i6300esb_reload_write(sc, (uint16_t)value);
		break;
	default:
		break;
	}
	(void)size;
}

static uint64_t
i6300esb_mmio_read(struct i6300esb_softc *sc, uint64_t offset, int size)
{
	uint64_t value;

	switch (offset) {
	case ESB_TIMER1_REG:
		value = sc->sc_timer1;
		break;
	case ESB_TIMER2_REG:
		value = sc->sc_timer2;
		break;
	case ESB_GINTSTS_REG:
		value = sc->sc_gintsts;
		break;
	case ESB_RELOAD_REG:
		value = sc->sc_timeout_flag ? ESB_WDT_TIMEOUT : 0;
		break;
	default:
		value = 0;
		break;
	}
	(void)size;
	return (value);
}

static void
i6300esb_barwrite(struct pci_devinst *pi, int baridx, uint64_t offset,
    int size, uint64_t value)
{
	struct i6300esb_softc *sc = pi->pi_arg;

	if (baridx != I6300ESB_BAR || offset >= I6300ESB_BAR_SIZE)
		return;
	pthread_mutex_lock(&sc->sc_mtx);
	i6300esb_mmio_write(sc, offset, size, value);
	pthread_mutex_unlock(&sc->sc_mtx);
}

static uint64_t
i6300esb_barread(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct i6300esb_softc *sc = pi->pi_arg;
	uint64_t value;

	if (baridx != I6300ESB_BAR || offset >= I6300ESB_BAR_SIZE)
		return (0);
	pthread_mutex_lock(&sc->sc_mtx);
	value = i6300esb_mmio_read(sc, offset, size);
	pthread_mutex_unlock(&sc->sc_mtx);
	return (value);
}

/* ---- CONFIG / LOCK register access (PCI config space) ---------------------- */

/*
 * Apply a LOCK-register write, honoring the sticky nature of the LOCKED and
 * ENABLE bits and starting/stopping the watchdog on an enable transition.
 */
static void
i6300esb_lock_write(struct i6300esb_softc *sc, uint8_t value)
{
	bool was_enabled, locked;

	locked = (sc->sc_lock & ESB_LOCK_LOCKED) != 0;
	was_enabled = (sc->sc_lock & ESB_LOCK_ENABLE) != 0;
	value &= ESB_LOCK_MASK;

	if (locked) {
		/* Once locked, ENABLE and LOCKED can only stay set. */
		value |= (sc->sc_lock & (ESB_LOCK_LOCKED | ESB_LOCK_ENABLE));
	}
	/* LOCKED is set-only regardless. */
	if ((sc->sc_lock & ESB_LOCK_LOCKED) != 0)
		value |= ESB_LOCK_LOCKED;

	sc->sc_lock = value;

	if (!was_enabled && (value & ESB_LOCK_ENABLE) != 0)
		i6300esb_start(sc);
	else if (was_enabled && (value & ESB_LOCK_ENABLE) == 0)
		i6300esb_stop(sc);
}

static int
i6300esb_cfgwrite(struct pci_devinst *pi, int offset, int bytes, uint32_t val)
{
	struct i6300esb_softc *sc = pi->pi_arg;
	int handled = 0;

	pthread_mutex_lock(&sc->sc_mtx);
	if (offset == ESB_CONFIG_REG && bytes == 2) {
		/* A locked configuration is immutable. */
		if ((sc->sc_lock & ESB_LOCK_LOCKED) == 0)
			sc->sc_config = (uint16_t)val & ESB_CFG_MASK;
		handled = 1;
	} else if (offset == ESB_LOCK_REG && bytes == 1) {
		i6300esb_lock_write(sc, (uint8_t)val);
		handled = 1;
	}
	pthread_mutex_unlock(&sc->sc_mtx);
	return (handled ? 0 : -1);
}

static int
i6300esb_cfgread(struct pci_devinst *pi, int offset, int bytes, uint32_t *rv)
{
	struct i6300esb_softc *sc = pi->pi_arg;
	int handled = 0;

	pthread_mutex_lock(&sc->sc_mtx);
	if (offset == ESB_CONFIG_REG && bytes == 2) {
		*rv = sc->sc_config;
		handled = 1;
	} else if (offset == ESB_LOCK_REG && bytes == 1) {
		*rv = sc->sc_lock;
		handled = 1;
	}
	pthread_mutex_unlock(&sc->sc_mtx);
	return (handled ? 0 : 1);
}

/* ---- init ------------------------------------------------------------------ */

static int
i6300esb_parse_config(struct i6300esb_softc *sc, nvlist_t *nvl)
{
	const char *value;

	sc->sc_action = I6300ESB_ACT_RESET;
	sc->sc_timeout = I6300ESB_DEFAULT_TIMEOUT;

	value = get_config_value_node(nvl, "action");
	if (value != NULL && !i6300esb_parse_action(value, &sc->sc_action)) {
		EPRINTLN("%s: invalid action \"%s\"", I6300ESB_NAME, value);
		return (-1);
	}

	value = get_config_value_node(nvl, "timeout");
	if (value != NULL) {
		int t = atoi(value);

		if (t <= 0 || t > I6300ESB_MAX_TIMEOUT) {
			EPRINTLN("%s: invalid timeout \"%s\" (1..%d)",
			    I6300ESB_NAME, value, I6300ESB_MAX_TIMEOUT);
			return (-1);
		}
		sc->sc_timeout = (uint32_t)t;
	}
	return (0);
}

static int
i6300esb_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct i6300esb_softc *sc;

	if (i6300esb_sc != NULL) {
		EPRINTLN("Only one i6300esb watchdog device is allowed.");
		return (-1);
	}

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return (-1);

	if (i6300esb_parse_config(sc, nvl) != 0) {
		free(sc);
		return (-1);
	}

	sc->sc_pi = pi;
	sc->sc_ctx = pi->pi_vmctx;
	sc->sc_bsp = vm_vcpu_open(pi->pi_vmctx, 0);
	pthread_mutex_init(&sc->sc_mtx, NULL);
	pi->pi_arg = sc;

	/* Preload both stages from the operator timeout by default. */
	sc->sc_timer1 = i6300esb_timeout_to_preload(sc->sc_timeout);
	sc->sc_timer2 = sc->sc_timer1;
	sc->sc_stage = 1;

	pci_set_cfgdata16(pi, PCIR_DEVICE, I6300ESB_DEVICE);
	pci_set_cfgdata16(pi, PCIR_VENDOR, I6300ESB_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, I6300ESB_CLASS);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, I6300ESB_SUBCLASS);
	pci_set_cfgdata8(pi, PCIR_HDRTYPE, PCIM_HDRTYPE_NORMAL);
	pci_set_cfgdata8(pi, PCIR_INTPIN, 0x1);

	if (pci_emul_alloc_bar(pi, I6300ESB_BAR, PCIBAR_MEM32,
	    I6300ESB_BAR_SIZE) != 0) {
		EPRINTLN("%s: failed to allocate BAR", I6300ESB_NAME);
		pi->pi_arg = NULL;
		free(sc);
		return (-1);
	}
	pci_lintr_request(pi);

	i6300esb_sc = sc;
	return (0);
}

#ifdef BHYVE_SNAPSHOT
/*
 * Portable, byte-packed checkpoint image.  Every field is serialized as
 * explicit little-endian bytes (no native-width SNAPSHOT_VAR) so a checkpoint
 * restores identically regardless of host word size or byte order.
 */
#define	I6300ESB_SNAP_VERSION	1
#define	I6300ESB_SNAP_LEN	24

static void
i6300esb_snap_encode(const struct i6300esb_softc *sc, uint8_t *b)
{

	b[0] = I6300ESB_SNAP_VERSION;
	b[1] = (uint8_t)sc->sc_action;
	b[2] = sc->sc_running ? 1 : 0;
	b[3] = sc->sc_stage;
	b[4] = sc->sc_timeout_flag ? 1 : 0;
	b[5] = sc->sc_unlock;
	b[6] = sc->sc_lock;
	b[7] = 0;			/* reserved / alignment */
	le16enc(&b[8], sc->sc_config);
	le16enc(&b[10], sc->sc_gintsts);
	le32enc(&b[12], sc->sc_timer1);
	le32enc(&b[16], sc->sc_timer2);
	le32enc(&b[20], sc->sc_timeout);
}

static int
i6300esb_snap_decode(struct i6300esb_softc *sc, const uint8_t *b)
{

	if (b[0] != I6300ESB_SNAP_VERSION)
		return (EINVAL);
	if (b[3] != 1 && b[3] != 2)
		return (EINVAL);
	sc->sc_action = (enum i6300esb_action)b[1];
	sc->sc_running = b[2] != 0;
	sc->sc_stage = b[3];
	sc->sc_timeout_flag = b[4] != 0;
	sc->sc_unlock = b[5];
	sc->sc_lock = b[6];
	sc->sc_config = le16dec(&b[8]);
	sc->sc_gintsts = le16dec(&b[10]);
	sc->sc_timer1 = le32dec(&b[12]);
	sc->sc_timer2 = le32dec(&b[16]);
	sc->sc_timeout = le32dec(&b[20]);
	return (0);
}

static int
i6300esb_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct i6300esb_softc *sc;
	uint8_t buf[I6300ESB_SNAP_LEN];
	int ret;

	if (meta == NULL || meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);

	if (meta->op == VM_SNAPSHOT_SAVE)
		i6300esb_snap_encode(sc, buf);

	SNAPSHOT_BUF_OR_LEAVE(buf, sizeof(buf), meta, ret, err);

	if (vm_snapshot_is_restoring(meta)) {
		ret = i6300esb_snap_decode(sc, buf);
		if (ret != 0)
			goto err;
		/* Re-arm the host timer for the restored stage. */
		if (sc->sc_running) {
			uint32_t preload = sc->sc_stage == 1 ?
			    sc->sc_timer1 : sc->sc_timer2;

			i6300esb_arm(sc, i6300esb_preload_to_ms(sc, preload));
		} else {
			i6300esb_disarm(sc);
		}
	}
	ret = 0;
err:
	return (ret);
}

/*
 * Decode the checkpoint image into a throwaway candidate to prove it is
 * well-formed before any of it is published to the live device.  This must
 * not mutate the live softc or touch the host timer (no arm/disarm); it only
 * exercises the same length and field validation as the restore path.
 */
static int
i6300esb_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct i6300esb_softc candidate;
	uint8_t buf[I6300ESB_SNAP_LEN];
	int ret;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);

	SNAPSHOT_BUF_OR_LEAVE(buf, sizeof(buf), meta, ret, err);
	ret = i6300esb_snap_decode(&candidate, buf);
err:
	return (ret);
}
#endif /* BHYVE_SNAPSHOT */

static const struct pci_devemu pci_de_i6300esb = {
	.pe_emu =	I6300ESB_NAME,
	.pe_init =	i6300esb_init,
	.pe_barwrite =	i6300esb_barwrite,
	.pe_barread =	i6300esb_barread,
	.pe_cfgwrite =	i6300esb_cfgwrite,
	.pe_cfgread =	i6300esb_cfgread,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	i6300esb_snapshot,
	.pe_snapshot_validate =	i6300esb_snapshot_validate,
#endif
};
PCI_EMUL_SET(pci_de_i6300esb);
