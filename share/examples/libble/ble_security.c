/*
 * ble_security.c — configure a pairing/security policy and pair with an agent.
 *
 * Usage: ble_security <addr> [public|random]
 *
 * Demonstrates the de-hardcoded security/pairing/privacy surface of libble:
 *   - build and apply a full security policy (SC + MITM + bonding) with
 *     ble_set_security_policy() (parity with NimBLE ble_hs_cfg.sm_*),
 *   - register as the runtime pairing agent and answer passkey / numeric-
 *     comparison / keypress prompts via the push-event callbacks,
 *   - turn LE privacy on,
 *   - pair, then read back the negotiated per-connection security with the
 *     structured ble_get_security_info() accessor.
 *
 * No secrets are printed beyond what an operator UI would already show
 * (the passkey / numeric-comparison value shown on the peer).
 */

#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ble.h>

static volatile int done;
static ble_addr_t target;

static void
on_passkey_display(const ble_addr_t *addr __unused, uint32_t passkey,
    void *arg __unused)
{

	printf("*** Enter this passkey on the peer: %06u ***\n", passkey);
}

static void
on_passkey_input(const ble_addr_t *addr, void *arg)
{
	ble_ctx_t *ctx = arg;
	unsigned int pk;

	printf("Enter the passkey shown on the peer: ");
	fflush(stdout);
	if (scanf("%u", &pk) == 1)
		ble_passkey_reply(ctx, addr, pk);
	else
		ble_passkey_reply(ctx, addr, 0);
}

static void
on_numcmp(const ble_addr_t *addr, uint32_t value, void *arg)
{
	ble_ctx_t *ctx = arg;
	char buf[8];

	printf("Does the peer show %06u? [y/n] ", value);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) != NULL &&
	    (buf[0] == 'y' || buf[0] == 'Y'))
		ble_numcmp_reply(ctx, addr, true);
	else
		ble_numcmp_reply(ctx, addr, false);
}

static void
on_keypress(const ble_addr_t *addr __unused, uint8_t type, void *arg __unused)
{
	static const char *const names[] = {
		"started", "digit entered", "digit erased", "cleared",
		"completed"
	};

	printf("[keypress] peer: %s\n",
	    type < 5 ? names[type] : "unknown");
}

static void
on_connected(const ble_addr_t *addr __unused, uint16_t handle __unused,
    const char *role __unused, uint16_t mtu __unused, void *arg)
{
	ble_ctx_t *ctx = arg;

	printf("Connected; pairing...\n");
	ble_pair(ctx, &target);
}

int
main(int argc, char *argv[])
{
	ble_ctx_t *ctx;
	ble_security_policy_t pol;
	ble_security_info_t info;
	struct pollfd pfd;
	int tries;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <addr> [public|random]\n", argv[0]);
		return (1);
	}
	memset(&target, 0, sizeof(target));
	if (ble_str_to_addr(argv[1], &target) < 0) {
		fprintf(stderr, "bad address: %s\n", argv[1]);
		return (1);
	}
	if (argc >= 3 && strcmp(argv[2], "random") == 0)
		target.addr_type = 1;

	ctx = ble_open(NULL);
	if (ctx == NULL) {
		fprintf(stderr, "ble_open: cannot connect to blued\n");
		return (1);
	}

	/*
	 * Coherent policy: LE Secure Connections only, MITM-authenticated,
	 * bonding on, distribute LTK+IRK+CSRK, floor at authenticated pairing.
	 * Every field keeps the daemon default unless set here.
	 */
	memset(&pol, 0, sizeof(pol));
	pol.mitm = true;
	pol.bonding = true;
	pol.sc_mode = BLE_SC_ONLY;
	pol.keypress = true;
	pol.io_cap = BLE_IO_KEYBOARD_DISPLAY;
	pol.min_security = BLE_SEC_SC;
	pol.min_key_size = 16;
	pol.key_dist = BLE_KEY_DIST_ENC | BLE_KEY_DIST_ID | BLE_KEY_DIST_SIGN;
	if (ble_set_security_policy(ctx, &pol) < 0)
		fprintf(stderr, "set security policy: %s\n", ble_strerror(ctx));

	/* Turn LE privacy on (RPAs for advertising/scanning/connecting). */
	if (ble_set_privacy(ctx, true) < 0)
		fprintf(stderr, "set privacy: %s\n", ble_strerror(ctx));

	/* Route pairing prompts to this process. */
	ble_on_passkey_display(ctx, on_passkey_display, NULL);
	ble_on_passkey_input(ctx, on_passkey_input, ctx);
	ble_on_numcmp(ctx, on_numcmp, ctx);
	ble_on_keypress(ctx, on_keypress, NULL);
	ble_on_connected(ctx, on_connected, ctx);
	if (ble_register_agent(ctx, BLE_IO_KEYBOARD_DISPLAY) < 0)
		fprintf(stderr, "register agent: %s\n", ble_strerror(ctx));

	if (ble_connect(ctx, &target, NULL, NULL) < 0) {
		fprintf(stderr, "connect: %s\n", ble_strerror(ctx));
		ble_close(ctx);
		return (1);
	}

	pfd.fd = ble_fd(ctx);
	pfd.events = POLLIN;
	for (tries = 0; tries < 300 && !done; tries++) {
		if (poll(&pfd, 1, 1000) > 0) {
			if (ble_process(ctx) < 0)
				break;
		}
		/* Once encrypted, report the negotiated security and stop. */
		if (ble_get_security_info(ctx, &target, &info) == 0 &&
		    info.encrypted) {
			printf("Secured: key_size=%u level=%u auth=%s sc=%s "
			    "bonded=%s\n", info.key_size, info.level,
			    info.authenticated ? "yes" : "no",
			    info.secure_connections ? "yes" : "no",
			    info.bonded ? "yes" : "no");
			done = 1;
		}
	}

	ble_unregister_agent(ctx);
	ble_close(ctx);
	return (done ? 0 : 1);
}
