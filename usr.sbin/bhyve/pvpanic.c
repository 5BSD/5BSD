/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Emulation of the QEMU "isa-pvpanic" paravirtual crash-notification device.
 *
 * The guest writes a byte to an I/O port when it panics (or loads a crash
 * kernel); the host observes the event and, per operator policy, logs it and
 * optionally changes the VM's lifecycle (poweroff/reset/halt) instead of
 * letting the guest hang silently.
 *
 * The device is presented on the LPC/ISA bus at I/O port 0x505 and described
 * in the ACPI DSDT with _HID "QEMU0001", which is exactly what the stock Linux
 * pvpanic driver binds to.
 */

#include <sys/types.h>
#include <machine/vmm.h>
#ifdef BHYVE_SNAPSHOT
#include <machine/vmm_snapshot.h>
#endif

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <vmmapi.h>

#include "acpi.h"
#include "amd64/inout.h"
#include "amd64/pci_lpc.h"
#include "config.h"
#include "debug.h"
#include "pvpanic.h"
#include "pvpanic_model.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif

#define	PVPANIC_IOPORT		0x505
#define	PVPANIC_IOLEN		1
#define	PVPANIC_NAME		"pvpanic"
#define	PVPANIC_ACPI_HID	"QEMU0001"

/*
 * The device is described by a config node "lpc.pvpanic" with a child
 * "enabled" flag and an optional "action".  The enable flag must be a child
 * of the node rather than the node itself: storing a value at "lpc.pvpanic"
 * would make "lpc.pvpanic.action" a child of an existing scalar, which the
 * config tree rejects with a fatal errx(3).
 */
#define	PVPANIC_CONFIG		"lpc.pvpanic.enabled"
#define	PVPANIC_CONFIG_ACTION	"lpc.pvpanic.action"

static bool		pvpanic_inited;
static enum pvpanic_action pvpanic_action = PVPANIC_ACT_NONE;

const char *
pvpanic_getname(void)
{

	return (PVPANIC_NAME);
}

static const char *
pvpanic_action_name(enum pvpanic_action act)
{

	switch (act) {
	case PVPANIC_ACT_POWEROFF:
		return ("poweroff");
	case PVPANIC_ACT_RESET:
		return ("reset");
	case PVPANIC_ACT_HALT:
		return ("halt");
	case PVPANIC_ACT_NONE:
	default:
		return ("log-only");
	}
}

int
pvpanic_parse(const char *opts)
{
	enum pvpanic_action act;
	const char *val;

	/*
	 * Accepted forms:
	 *   -l pvpanic
	 *   -l pvpanic,action=none|log|poweroff|reset|halt
	 * The bare form defaults to log-only, the fail-safe policy.
	 */
	set_config_bool(PVPANIC_CONFIG, true);

	if (opts == NULL || *opts == '\0')
		return (0);

	if (strncmp(opts, "action=", 7) == 0)
		val = opts + 7;
	else
		val = opts;

	if (!pvpanic_parse_action(val, &act)) {
		EPRINTLN("pvpanic: invalid action \"%s\"", val);
		return (-1);
	}
	set_config_value(PVPANIC_CONFIG_ACTION, val);
	return (0);
}

static void
pvpanic_react(struct vmctx *ctx, uint8_t events)
{
	enum vm_suspend_how how;
	int error;

	/* Log clearly which device and which event(s) the guest reported. */
	EPRINTLN("%s: guest reported event 0x%02x (%s%s%s)", PVPANIC_NAME,
	    events,
	    (events & PVPANIC_PANICKED) ? "PANICKED" : "",
	    ((events & PVPANIC_SUPPORTED_EVENTS) == PVPANIC_SUPPORTED_EVENTS) ?
	    "+" : "",
	    (events & PVPANIC_CRASHLOADED) ? "CRASHLOADED" : "");

	/*
	 * Only a PANICKED event is fatal and may drive a lifecycle change; a
	 * CRASHLOADED guest is (about to be) running a crashkernel and must be
	 * left alone to capture the dump.  Reuse bhyve's existing guest-request
	 * suspend machinery rather than inventing a new exit path.
	 */
	if (!pvpanic_event_is_fatal(events) ||
	    pvpanic_action == PVPANIC_ACT_NONE)
		return;

	switch (pvpanic_action) {
	case PVPANIC_ACT_POWEROFF:
		how = VM_SUSPEND_POWEROFF;
		break;
	case PVPANIC_ACT_RESET:
		how = VM_SUSPEND_RESET;
		break;
	case PVPANIC_ACT_HALT:
		how = VM_SUSPEND_HALT;
		break;
	default:
		return;
	}

	EPRINTLN("%s: applying host action \"%s\" on guest panic", PVPANIC_NAME,
	    pvpanic_action_name(pvpanic_action));
	error = vm_suspend(ctx, how);
	if (error != 0 && errno != EALREADY)
		EPRINTLN("%s: vm_suspend failed: %s", PVPANIC_NAME,
		    strerror(errno));
}

static int
pvpanic_io(struct vmctx *ctx, int in, int port __unused, int bytes,
    uint32_t *eax, void *arg __unused)
{
	uint8_t events;

	if (bytes != 1)
		return (-1);

	if (in) {
		/* Read yields the supported-events bitmap. */
		*eax = pvpanic_supported_events();
		return (0);
	}

	/* Write: decode the event; unknown bits are ignored per the ABI. */
	events = pvpanic_decode_event((uint8_t)*eax);
	if (events != 0)
		pvpanic_react(ctx, events);
	return (0);
}

int
pvpanic_init(struct vmctx *ctx __unused)
{
	struct inout_port iop;
	const char *action;
	int error;

	if (pvpanic_inited) {
		EPRINTLN("Only one pvpanic device is allowed.");
		return (-1);
	}

	action = get_config_value(PVPANIC_CONFIG_ACTION);
	if (action != NULL && !pvpanic_parse_action(action, &pvpanic_action)) {
		EPRINTLN("pvpanic: invalid action \"%s\"", action);
		return (-1);
	}

	memset(&iop, 0, sizeof(iop));
	iop.name = PVPANIC_NAME;
	iop.port = PVPANIC_IOPORT;
	iop.size = PVPANIC_IOLEN;
	iop.flags = IOPORT_F_INOUT;
	iop.handler = pvpanic_io;
	iop.arg = NULL;

	error = register_inout(&iop);
	if (error != 0) {
		EPRINTLN("pvpanic: failed to register I/O port 0x%x",
		    PVPANIC_IOPORT);
		return (error);
	}

	pvpanic_inited = true;
	return (0);
}

/*
 * Append the pvpanic ACPI node to the DSDT.  Emitted inside the ISA device
 * scope only when the device is actually configured, so stock guest drivers
 * that key off _HID "QEMU0001" bind to the port we registered above.
 */
static void
pvpanic_write_dsdt(void)
{

	if (!pvpanic_inited)
		return;

	dsdt_line("");
	dsdt_line("Device (PEVT)");
	dsdt_line("{");
	dsdt_line("  Name (_HID, \"%s\")", PVPANIC_ACPI_HID);
	dsdt_line("  Name (_STA, 0x0F)");
	dsdt_line("  Name (_CRS, ResourceTemplate ()");
	dsdt_line("  {");
	dsdt_indent(2);
	dsdt_fixed_ioport(PVPANIC_IOPORT, PVPANIC_IOLEN);
	dsdt_unindent(2);
	dsdt_line("  })");
	dsdt_line("}");
}
LPC_DSDT(pvpanic_write_dsdt);

#ifdef BHYVE_SNAPSHOT
int
pvpanic_snapshot(struct vm_snapshot_meta *meta)
{
	uint8_t config;
	bool enabled;
	enum pvpanic_action action;
	int ret;

	/*
	 * The event register itself is stateless (constant read, write-only
	 * trigger), so the only checkpointable state is the enable flag and the
	 * armed host action, packed into a single config byte.  A device with a
	 * NULL snapshot handler would fail the whole VM checkpoint, so provide
	 * one even though the payload is tiny.
	 */
	config = pvpanic_config_encode(pvpanic_inited, pvpanic_action);
	SNAPSHOT_BUF_OR_LEAVE(&config, sizeof(config), meta, ret, err);
	if (vm_snapshot_is_restoring(meta)) {
		if (!pvpanic_config_decode(config, &enabled, &action)) {
			ret = EINVAL;
			goto err;
		}
		pvpanic_inited = enabled;
		pvpanic_action = action;
	}
err:
	return (ret);
}
#endif
