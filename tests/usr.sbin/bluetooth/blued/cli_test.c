/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF tests for the bluedctl argument joiner (finding K1).
 *
 * K1 is a CRITICAL stack out-of-bounds write: the connect-name path
 * accumulated snprintf() return values (the *untruncated* would-be length)
 * into a running offset, so once the joined arguments crossed the 512-byte
 * buffer the offset walked past the end.  On the next iteration
 * "sizeof(buf) - off" underflows to ~2^64 and "buf + off" is out of bounds,
 * giving snprintf an unbounded destination — a stack smash reachable from
 * argv and from interactive input.
 *
 * bluedctl.c is a PROG with a static join_args(); this test
 * #includes the translation unit (with main() renamed out of the way) so the
 * real, shipping functions are exercised directly.  join_args() is checked
 * with a canary/guard region immediately after the destination buffer to prove
 * it never writes past the end.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <string.h>

#include "ipc_proto.h"

#define main bluedctl_main_unused
#include "bluedctl.c"
#undef main

#include <atf-c.h>

/* Coverage builds expose these runtime hooks.  Weak references keep ordinary
 * non-instrumented test builds linkable. */
extern int __llvm_profile_set_file_object(FILE *, int)
    __attribute__((weak));
extern int __llvm_profile_write_file(void) __attribute__((weak));

/* ================================================================
 * join_args(): canary/guard region proves no out-of-bounds write.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(k1_join_args_canary);
ATF_TC_BODY(k1_join_args_canary, tc)
{
	struct {
		char	buf[32];
		char	canary[64];
	} g;
	char cmd[] = "connect-name";
	char seg[] = "AAAAAAAAAAAAAAAA";	/* 16 chars each */
	char *av[8];
	int i, rc;

	memset(g.canary, 0x5A, sizeof(g.canary));

	/* Several args whose joined length far exceeds the 32-byte buffer. */
	av[0] = cmd;
	for (i = 1; i < 8; i++)
		av[i] = seg;

	rc = join_args(g.buf, sizeof(g.buf), 8, av, 1);

	/* Must report overflow, not silently truncate a security-relevant cmd. */
	ATF_CHECK_EQ(rc, -1);
	/* Buffer stays NUL-terminated strictly within bounds. */
	ATF_CHECK(memchr(g.buf, '\0', sizeof(g.buf)) != NULL);
	ATF_CHECK_EQ(g.buf[sizeof(g.buf) - 1], '\0');
	/* The guard region immediately after buf is untouched. */
	for (i = 0; i < (int)sizeof(g.canary); i++)
		ATF_CHECK_EQ((unsigned char)g.canary[i], 0x5A);
}

/* A joined string that fits succeeds and is exactly the space-joined args. */
ATF_TC_WITHOUT_HEAD(k1_join_args_fits);
ATF_TC_BODY(k1_join_args_fits, tc)
{
	char buf[64];
	char a0[] = "connect-name", a1[] = "My", a2[] = "Cool", a3[] = "Device";
	char *av[4] = { a0, a1, a2, a3 };
	int rc;

	rc = join_args(buf, sizeof(buf), 4, av, 1);
	ATF_CHECK_EQ(rc, 0);
	ATF_CHECK_STREQ(buf, "My Cool Device");
}

ATF_TC_WITHOUT_HEAD(cli_pure_helper_matrix);
ATF_TC_BODY(cli_pure_helper_matrix, tc)
{
	static const char *const names[] = { "read", "write", "notify" };
	static const uint8_t bits[] = { 1, 2, 4 };
	ble_uuid_t uuid;
	uint8_t bytes[8], mask;
	uint16_t length;
	uint32_t value;
	bool enabled;
	char empty[] = "";
	char oversized_mask[160];
	char *none[1] = { empty };

	got_sigint = 0;
	sigint_handler(SIGINT);
	ATF_CHECK_EQ(1, got_sigint);
	ATF_CHECK_EQ(EX_OK, map_exit_code(BLE_ERR_NONE));
	ATF_CHECK_EQ(EX_PERM, map_exit_code(BLE_ERR_PERM));
	ATF_CHECK_EQ(EX_BUSY, map_exit_code(BLE_ERR_BUSY));
	ATF_CHECK_EQ(EX_TIMEOUT, map_exit_code(BLE_ERR_TIMEOUT));
	ATF_CHECK_EQ(EX_NOTCONN, map_exit_code(BLE_ERR_NOTCONN));
	ATF_CHECK_EQ(EX_NOTCONN, map_exit_code(BLE_ERR_NOTFOUND));
	ATF_CHECK_EQ(EX_USAGE, map_exit_code(BLE_ERR_INVAL));
	ATF_CHECK_EQ(EX_ERR, map_exit_code(999));

	print_error_hint(BLE_ERR_PERM);
	print_error_hint(BLE_ERR_NOTCONN);
	print_error_hint(BLE_ERR_BUSY);
	print_error_hint(BLE_ERR_TIMEOUT);
	print_error_hint(BLE_ERR_NONE);
	ATF_CHECK(looks_like_addr("01:02:03:04:05:06"));
	ATF_CHECK(!looks_like_addr("not-an-address"));
	memset(oversized_mask, 'a', sizeof(oversized_mask));
	oversized_mask[sizeof(oversized_mask) - 1] = '\0';
	ATF_CHECK_EQ(-1, parse_name_mask(oversized_mask, names, bits,
	    nitems(names), &mask));

	json_mode = false;
	print_result_line("plain");
	json_mode = true;
	print_result_line("quote=\" slash=\\ newline=\n return=\r tab=\t\001");
	json_mode = false;

	ATF_CHECK_EQ(-1, join_args(empty, 0, 1, none, 0));
	ATF_CHECK_EQ(0, parse_u32("0x10", 1, 20, &value));
	ATF_CHECK_EQ(16, value);
	ATF_CHECK_EQ(-1, parse_u32("", 0, 20, &value));
	ATF_CHECK_EQ(-1, parse_u32("12x", 0, 20, &value));
	ATF_CHECK_EQ(-1, parse_u32("21", 0, 20, &value));
	ATF_CHECK_EQ(0, parse_switch("on", &enabled));
	ATF_CHECK(enabled);
	ATF_CHECK_EQ(0, parse_switch("NO", &enabled));
	ATF_CHECK(!enabled);
	ATF_CHECK_EQ(-1, parse_switch("maybe", &enabled));
	ATF_CHECK_EQ(0, parse_hex_value("00aBff", bytes, sizeof(bytes),
	    &length));
	ATF_CHECK_EQ(3, length);
	ATF_CHECK_EQ(0xab, bytes[1]);
	ATF_CHECK_EQ(-1, parse_hex_value("0", bytes, sizeof(bytes), &length));
	ATF_CHECK_EQ(-1, parse_hex_value("0000", bytes, 1, &length));
	ATF_CHECK_EQ(-1, parse_hex_value("zz", bytes, sizeof(bytes), &length));
	ATF_CHECK_EQ(0, parse_uuid16("0x180f", &uuid));
	ATF_CHECK_EQ(0x180f, uuid.uuid16);
	ATF_CHECK_EQ(-1, parse_uuid16("0", &uuid));
	ATF_CHECK_EQ(0, parse_name_mask("read,notify", names, bits, 3, &mask));
	ATF_CHECK_EQ(5, mask);
	ATF_CHECK_EQ(-1, parse_name_mask("read,bogus", names, bits, 3, &mask));
}

ATF_TC_WITHOUT_HEAD(cli_callback_and_help_matrix);
ATF_TC_BODY(cli_callback_and_help_matrix, tc)
{
	struct typed_wait wait;
	struct profile_state profile;
	ble_addr_t addr;
	ble_service_t service;
	ble_characteristic_t characteristic;
	ble_scan_result_t scan;
	uint8_t payload[] = { 0x00, 0x7f, 0xff };

	memset(&addr, 0, sizeof(addr));
	memset(&service, 0, sizeof(service));
	memset(&characteristic, 0, sizeof(characteristic));
	service.start_handle = 1;
	service.end_handle = 5;
	service.uuid.uuid16 = 0x180f;
	characteristic.handle = 3;
	characteristic.properties = 2;
	characteristic.uuid.uuid16 = 0x2a19;

	memset(&wait, 0, sizeof(wait));
	typed_connect_cb(&addr, 7, &wait);
	ATF_CHECK(wait.done);
	ATF_CHECK_EQ(7, wait.status);
	memset(&wait, 0, sizeof(wait));
	typed_discover_cb(&addr, &service, 1, &characteristic, 1, &wait);
	ATF_CHECK(wait.done);
	memset(&wait, 0, sizeof(wait));
	typed_read_cb(&addr, 3, payload, sizeof(payload), 0, &wait);
	ATF_CHECK(wait.done);
	typed_read_cb(&addr, 3, payload, sizeof(payload), 9, &wait);

	memset(&scan, 0, sizeof(scan));
	scan.addr = addr;
	scan.rssi = -42;
	strlcpy(scan.name, "mesh-node", sizeof(scan.name));
	json_mode = false;
	typed_scan_cb(&scan, NULL);
	json_mode = true;
	typed_scan_cb(&scan, NULL);

	memset(&profile, 0, sizeof(profile));
	profile.target_chr = characteristic.uuid.uuid16;
	profile_discover_cb(&addr, &service, 1, &characteristic, 1, &profile);
	ATF_CHECK_EQ(characteristic.handle, profile.found_handle);
	memset(&profile, 0, sizeof(profile));
	profile.target_chr = 0xffff;
	profile_discover_cb(&addr, &service, 1, &characteristic, 1, &profile);
	ATF_CHECK(profile.done);
	profile_read_cb(&addr, 3, payload, sizeof(payload), 0, &profile);

	json_mode = false;
	mon_connected_cb(&addr, 1, 247, NULL);
	mon_disconnected_cb(&addr, 19, NULL);
	mon_passkey_display_cb(&addr, 123456, NULL);
	mon_passkey_input_cb(&addr, NULL);
	mon_numcmp_cb(&addr, 654321, NULL);
	mon_notify_cb(&addr, 3, payload, sizeof(payload), NULL);
	json_mode = true;
	mon_connected_cb(&addr, 1, 247, NULL);
	mon_disconnected_cb(&addr, 19, NULL);
	mon_passkey_display_cb(&addr, 123456, NULL);
	mon_passkey_input_cb(&addr, NULL);
	mon_numcmp_cb(&addr, 654321, NULL);
	mon_notify_cb(&addr, 3, payload, sizeof(payload), NULL);
	json_mode = false;

	print_command_help("status");
	print_command_help("definitely-unknown");
}

ATF_TC_WITHOUT_HEAD(cli_workflow_helper_matrix);
ATF_TC_BODY(cli_workflow_helper_matrix, tc)
{
	struct kbd_state ks;
	ble_addr_t addr, other;
	uint8_t bytes[4];
	uint16_t length;
	char prog[] = "bluedctl", help[] = "help", status[] = "status";
	char keyboard[] = "keyboard", bad[] = "bad-address";
	char find[] = "find";
	char *helpv[] = { prog, help };
	char *statusv[] = { prog, help, status };
	char *badv[] = { prog, keyboard, bad };
	char *findv[] = { find, bad };

	ATF_CHECK_EQ(0, parse_hex_bytes("00aBff", bytes, sizeof(bytes),
	    &length));
	ATF_CHECK_EQ(3, length);
	ATF_CHECK_EQ(0xab, bytes[1]);
	ATF_CHECK_EQ(-1, parse_hex_bytes("0", bytes, sizeof(bytes), &length));
	ATF_CHECK_EQ(-1, parse_hex_bytes("0000000000", bytes, sizeof(bytes),
	    &length));
	ATF_CHECK_EQ(-1, parse_hex_bytes("zz", bytes, sizeof(bytes), &length));

	memset(&addr, 0, sizeof(addr));
	memset(&other, 1, sizeof(other));
	memset(&ks, 0, sizeof(ks));
	strlcpy(ks.addr, "00:00:00:00:00:00", sizeof(ks.addr));
	kbd_connected_cb(&other, 1, 23, &ks);
	ATF_CHECK(!ks.done);
	kbd_passkey_display_cb(&other, 123456, &ks);
	kbd_passkey_input_cb(&other, &ks);
	kbd_numcmp_cb(&other, 123456, &ks);
	kbd_connected_cb(&addr, 2, 247, &ks);
	ATF_CHECK(ks.done);
	ATF_CHECK_EQ(EX_OK, ks.ret);
	ks.done = false;
	kbd_disconnected_cb(&addr, 19, &ks);
	ATF_CHECK(ks.done);
	ATF_CHECK_EQ(EX_ERR, ks.ret);
	ks.done = false;
	kbd_connect_ack_cb(&addr, 0, &ks);
	ATF_CHECK(!ks.done);
	kbd_connect_ack_cb(&addr, 1, &ks);
	ATF_CHECK(ks.done);
	ATF_CHECK_EQ(0, handle_profile_cmd(NULL, 1, helpv + 1));
	ATF_CHECK_EQ(-1, handle_profile_cmd(NULL, 2, findv));

	/* main's daemon-free help and pre-connect validation paths. */
	optind = 1;
	ATF_CHECK_EQ(EX_OK, bluedctl_main_unused(2, helpv));
	optind = 1;
	ATF_CHECK_EQ(EX_OK, bluedctl_main_unused(3, statusv));
	optind = 1;
	ATF_CHECK_EQ(EX_USAGE, bluedctl_main_unused(3, badv));
}

/*
 * Drive every typed-command grammar through the real libble entry point.
 * A closed peer makes request submission fail immediately, so callback-based
 * commands cover their error path without waiting for a daemon timeout.
 */
ATF_TC_WITHOUT_HEAD(cli_typed_dispatch_matrix);
ATF_TC_BODY(cli_typed_dispatch_matrix, tc)
{
	static const char *const commands[][6] = {
		{ "scan" },
		{ "connect", "01:02:03:04:05:06" },
		{ "connect", "01:02:03:04:05:06", "random" },
		{ "connect-name", "test", "device" },
		{ "disconnect", "01:02:03:04:05:06" },
		{ "pair", "01:02:03:04:05:06" },
		{ "unbond", "01:02:03:04:05:06" },
		{ "rekey", "01:02:03:04:05:06" },
		{ "discover", "01:02:03:04:05:06" },
		{ "read", "01:02:03:04:05:06", "1" },
		{ "write", "01:02:03:04:05:06", "1", "00ff" },
		{ "write-cmd", "01:02:03:04:05:06", "1", "00ff" },
		{ "subscribe", "01:02:03:04:05:06", "1" },
		{ "unsubscribe", "01:02:03:04:05:06", "1" },
		{ "set-value", "1", "00ff" },
		{ "add-service", "0x180f" },
		{ "add-char", "1", "0x2a19", "read,notify", "read", "64" },
		{ "gatt-begin" }, { "gatt-commit" }, { "gatt-rollback" },
		{ "remove-service", "1" },
		{ "adv-data", "020106" }, { "scan-resp", "020106" },
		{ "advertise", "on" }, { "advertise", "off" },
		{ "pairable", "on" }, { "privacy", "off" },
		{ "power", "on" }, { "power", "off", "adapter=2" },
		{ "set-mtu", "247" }, { "set-name", "test", "adapter" },
		{ "discoverable", "on", "30", "limited" },
		{ "discoverable", "off", "0", "general" },
		{ "bond-export", "01:02:03:04:05:06" },
		{ "connparams-update", "01:02:03:04:05:06", "6", "12", "0", "50" },
		{ "set-phy", "01:02:03:04:05:06", "1", "2" },
		{ "set-data-len", "01:02:03:04:05:06", "251", "2120" },
		{ "passkey", "01:02:03:04:05:06", "123456" },
		{ "confirm", "01:02:03:04:05:06", "yes" },
		{ "eatt-open", "01:02:03:04:05:06", "3" },
		{ "eatt-close", "01:02:03:04:05:06" },
	};
	static const char *const bad[][6] = {
		{ "connect", "bad" }, { "connect", "01:02:03:04:05:06", "bogus" },
		{ "disconnect", "bad" }, { "pair", "bad" },
		{ "unbond", "bad" }, { "rekey", "bad" },
		{ "discover", "bad" },
		{ "read", "01:02:03:04:05:06", "0" },
		{ "write", "bad", "1", "0" }, { "set-value", "0", "zz" },
		{ "write-cmd", "bad", "1", "00" },
		{ "subscribe", "bad", "1" }, { "unsubscribe", "bad", "1" },
		{ "add-service", "0" }, { "add-char", "1", "1", "bogus", "read" },
		{ "remove-service", "0" }, { "adv-data", "0" },
		{ "scan-resp", "0" }, { "advertise", "maybe" },
		{ "pairable", "maybe" }, { "privacy", "maybe" },
		{ "power", "on", "adapter=bogus" },
		{ "set-mtu", "22" }, { "discoverable", "on", "3601" },
		{ "discoverable", "on", "1", "bogus" },
		{ "bond-export", "bad" },
		{ "connparams-update", "bad", "1", "1", "1", "1" },
		{ "set-phy", "01:02:03:04:05:06", "8", "1" },
		{ "set-data-len", "01:02:03:04:05:06", "26", "328" },
		{ "passkey", "01:02:03:04:05:06", "1000000" },
		{ "confirm", "01:02:03:04:05:06", "maybe" },
		{ "eatt-open", "01:02:03:04:05:06", "0" },
		{ "eatt-close", "bad" },
		{ "unknown" },
	};
	ble_ctx_t *ctx;
	int sp[2], argc;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	close(sp[1]);
	(void)signal(SIGPIPE, SIG_IGN);

	for (size_t i = 0; i < nitems(commands); i++) {
		for (argc = 0; argc < (int)nitems(commands[i]) &&
		    commands[i][argc] != NULL; argc++)
			;
		ATF_CHECK_MSG(handle_typed_command(ctx, argc,
		    __DECONST(char **, commands[i])) == -1,
		    "valid command was not dispatched: %s", commands[i][0]);
	}
	for (size_t i = 0; i < nitems(bad); i++) {
		for (argc = 0; argc < (int)nitems(bad[i]) && bad[i][argc] != NULL;
		    argc++)
			;
		ATF_CHECK(handle_typed_command(ctx, argc,
		    __DECONST(char **, bad[i])) <= 0);
	}
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(cli_query_profile_help_matrix);
ATF_TC_BODY(cli_query_profile_help_matrix, tc)
{
	static const char *const queries[][3] = {
		{ "status" }, { "adapters" }, { "adapter-caps" },
		{ "list" }, { "list", "bad-address" }, { "conninfo" },
		{ "connparams" }, { "phy" }, { "bonds" },
		{ "resolv", "list" }, { "unknown" },
	};
	static const char *const profiles[][3] = {
		{ "battery", "01:02:03:04:05:06" },
		{ "devinfo", "01:02:03:04:05:06" },
		{ "heart-rate", "01:02:03:04:05:06" },
		{ "thermometer", "01:02:03:04:05:06" },
		{ "time", "01:02:03:04:05:06" },
		{ "find", "01:02:03:04:05:06" }, { "unknown" },
	};
	static const char *const help_names[] = {
		"status", "adapters", "adapter-caps", "scan", "list", "connect",
		"connect-name", "disconnect", "pair", "bonds", "unbond", "rekey",
		"discover", "read", "write", "write-cmd", "subscribe", "unsubscribe",
		"set-value", "add-service", "add-char", "gatt-begin", "gatt-commit",
		"gatt-rollback", "remove-service", "adv-data", "scan-resp", "advertise",
		"pairable", "privacy", "power", "set-mtu", "set-name", "discoverable",
		"bond-export", "connparams", "connparams-update", "set-phy",
		"set-data-len", "passkey", "confirm", "eatt-open", "eatt-close",
		"battery", "devinfo", "heart-rate", "thermometer", "time", "find",
		"monitor", "serve", "keyboard", "unknown"
	};
	ble_ctx_t *ctx;
	int sp[2], argc;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	close(sp[1]);
	(void)signal(SIGPIPE, SIG_IGN);
	for (size_t i = 0; i < nitems(queries); i++) {
		for (argc = 0; argc < (int)nitems(queries[i]) &&
		    queries[i][argc] != NULL; argc++)
			;
		ATF_CHECK(handle_structured_query(ctx, argc,
		    __DECONST(char **, queries[i])) <= 0);
	}
	for (size_t i = 0; i < nitems(profiles); i++) {
		for (argc = 0; argc < (int)nitems(profiles[i]) &&
		    profiles[i][argc] != NULL; argc++)
			;
		ATF_CHECK(handle_profile_cmd(ctx, argc,
		    __DECONST(char **, profiles[i])) <= 0);
	}
	for (size_t i = 0; i < nitems(help_names); i++)
		print_command_help(help_names[i]);
	print_help();
	ble_close(ctx);
}

static void
stage_cli_frame(int fd, uint16_t domain, uint32_t request_id,
    const void *body, size_t body_len)
{
	uint8_t hdr[IPC_HDR_SIZE];
	uint8_t payload[IPC_OP_PREFIX_SIZE + 256];

	ATF_REQUIRE(body_len <= sizeof(payload) - IPC_OP_PREFIX_SIZE);
	ipc_op_prefix_encode(payload, request_id, IPC_ERR_NONE, 0);
	if (body_len != 0)
		memcpy(payload + IPC_OP_PREFIX_SIZE, body, body_len);
	ipc_hdr_encode(hdr, IPC_OP_PREFIX_SIZE + body_len, IPC_T_OP_REPLY,
	    domain);
	ATF_REQUIRE_EQ((ssize_t)sizeof(hdr), write(fd, hdr, sizeof(hdr)));
	ATF_REQUIRE_EQ((ssize_t)(IPC_OP_PREFIX_SIZE + body_len),
	    write(fd, payload, IPC_OP_PREFIX_SIZE + body_len));
}

static int
run_staged_query(const char *const *argv, int argc, uint16_t domain,
    const void *body, size_t body_len)
{
	ble_ctx_t *ctx;
	int sp[2], rc;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	stage_cli_frame(sp[1], domain, 1, body, body_len);
	rc = handle_structured_query(ctx, argc, __DECONST(char **, argv));
	ble_close(ctx);
	close(sp[1]);
	return (rc);
}

static int
run_staged_typed(const char *const *argv, int argc, uint16_t domain,
    const void *body, size_t body_len)
{
	ble_ctx_t *ctx;
	int sp[2], rc;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	stage_cli_frame(sp[1], domain, 1, body, body_len);
	rc = handle_typed_command(ctx, argc, __DECONST(char **, argv));
	ble_close(ctx);
	close(sp[1]);
	return (rc);
}

ATF_TC_WITHOUT_HEAD(cli_typed_success_matrix);
ATF_TC_BODY(cli_typed_success_matrix, tc)
{
	static const char *const connect[] = {
		"connect", "01:02:03:04:05:06"
	};
	static const char *const connect_name[] = {
		"connect-name", "named", "peer"
	};
	static const char *const discover[] = {
		"discover", "01:02:03:04:05:06"
	};
	static const char *const read[] = {
		"read", "01:02:03:04:05:06", "42"
	};
	static const char *const add_service[] = {
		"add-service", "0x180f"
	};
	static const char *const add_char[] = {
		"add-char", "1", "0x2a19", "read,notify", "read", "64"
	};
	uint8_t name_reply[IPC_GAP_CONNECT_NAME_REPLY_SIZE] = { 0 };
	uint8_t read_reply[IPC_GATT_READ_REPLY_SIZE + 2] = { 0 };
	uint8_t handle_reply[IPC_GATT_HANDLE_REPLY_SIZE] = { 0 };

	name_reply[0] = 1;
	memset(name_reply + 1, 0x44, 6);
	ATF_CHECK_EQ(1, run_staged_typed(connect, 2, IPC_OP_DOMAIN_GAP,
	    NULL, 0));
	ATF_CHECK_EQ(1, run_staged_typed(connect_name, 3, IPC_OP_DOMAIN_GAP,
	    name_reply, sizeof(name_reply)));
	ATF_CHECK_EQ(1, run_staged_typed(discover, 2, IPC_OP_DOMAIN_GATT,
	    NULL, 0));

	ipc_put_le16(read_reply, IPC_GATT_READ);
	ipc_put_le16(read_reply + 2, 42);
	ipc_put_le16(read_reply + 4, 2);
	read_reply[6] = 0xaa;
	read_reply[7] = 0x55;
	ATF_CHECK_EQ(1, run_staged_typed(read, 3, IPC_OP_DOMAIN_GATT,
	    read_reply, sizeof(read_reply)));

	ipc_put_le16(handle_reply, IPC_GATT_ADD_SERVICE);
	ipc_put_le16(handle_reply + 2, 0x100);
	ATF_CHECK_EQ(1, run_staged_typed(add_service, 2, IPC_OP_DOMAIN_GATT,
	    handle_reply, sizeof(handle_reply)));
	ipc_put_le16(handle_reply, IPC_GATT_ADD_CHARACTERISTIC);
	ipc_put_le16(handle_reply + 2, 0x101);
	ATF_CHECK_EQ(1, run_staged_typed(add_char, 6, IPC_OP_DOMAIN_GATT,
	    handle_reply, sizeof(handle_reply)));
}

ATF_TC_WITHOUT_HEAD(cli_query_success_matrix);
ATF_TC_BODY(cli_query_success_matrix, tc)
{
	static const char *const connection_queries[][2] = {
		{ "list" }, { "list", "01:02:03:04:05:06" },
		{ "conninfo" }, { "connparams" }, { "phy" }
	};
	static const char *const statusv[] = { "status" };
	static const char *const adaptersv[] = { "adapters" };
	static const char *const capsv[] = { "adapter-caps", "0" };
	static const char *const badcapsv[] = { "adapter-caps", "9" };
	static const char *const bondsv[] = { "bonds" };
	static const char *const resolvv[] = { "resolv", "list" };
	uint8_t status[IPC_STATUS_REPLY_SIZE];
	uint8_t caps[IPC_ADAPTER_CAPS_REPLY_SIZE];
	uint8_t conn[IPC_GAP_CONNECTION_REPLY_HDR_SIZE +
	    IPC_GAP_CONNECTION_RECORD_SIZE];
	uint8_t bonds[IPC_SECURITY_BOND_REPLY_HDR_SIZE +
	    IPC_SECURITY_BOND_RECORD_SIZE];
	uint8_t resolv[IPC_SECURITY_RESOLV_REPLY_HDR_SIZE +
	    IPC_SECURITY_RESOLV_RECORD_SIZE];
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	ble_ctx_t *ctx;
	int sp[2];

	ipc_status_reply_encode(status, 1, 1, 2, IPC_STATUS_F_PERIPH_ACTIVE);
	ATF_CHECK_EQ(1, run_staged_query(statusv, 1, IPC_OP_DOMAIN_CTL,
	    status, sizeof(status)));

	/* The adapters query consumes status request 1 and caps request 2. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	stage_cli_frame(sp[1], IPC_OP_DOMAIN_CTL, 1, status, sizeof(status));
	memset(caps, 0, sizeof(caps));
	ipc_adapter_caps_reply_encode(caps, 0, "ubt0", addr, 0, 1,
	    0x1234);
	stage_cli_frame(sp[1], IPC_OP_DOMAIN_CTL, 2, caps, sizeof(caps));
	ATF_CHECK_EQ(1, handle_structured_query(ctx, 1,
	    __DECONST(char **, adaptersv)));
	ble_close(ctx);
	close(sp[1]);

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	stage_cli_frame(sp[1], IPC_OP_DOMAIN_CTL, 1, status, sizeof(status));
	ipc_adapter_caps_reply_encode(caps, 0, "ubt0", addr, 1, 1,
	    UINT64_MAX);
	stage_cli_frame(sp[1], IPC_OP_DOMAIN_CTL, 2, caps, sizeof(caps));
	ATF_CHECK_EQ(1, handle_structured_query(ctx, 2,
	    __DECONST(char **, capsv)));
	ble_close(ctx);
	close(sp[1]);
	ATF_CHECK_EQ(-1, run_staged_query(badcapsv, 2, IPC_OP_DOMAIN_CTL,
	    status, sizeof(status)));

	memset(conn, 0, sizeof(conn));
	ipc_put_le16(conn, IPC_GAP_GET_CONNECTIONS);
	ipc_put_le16(conn + 2, 1);
	conn[4] = 0;
	memcpy(conn + 5, addr, sizeof(addr));
	conn[11] = 2;                 /* connected */
	conn[12] = 0;                 /* central */
	conn[13] = IPC_GAP_CONN_F_ENCRYPTED | IPC_GAP_CONN_F_AUTHENTICATED |
	    IPC_GAP_CONN_F_PHY_VALID;
	conn[14] = 16;                /* key size */
	conn[15] = 2; conn[16] = 2;  /* symmetric 2M PHY */
	conn[17] = 0;
	ipc_put_le16(conn + 18, 0x40);
	ipc_put_le16(conn + 20, 247);
	ipc_put_le16(conn + 22, 24);
	ipc_put_le16(conn + 24, 0);
	ipc_put_le16(conn + 26, 200);
	strlcpy((char *)conn + 28, "peer", 64);
	for (size_t i = 0; i < nitems(connection_queries); i++)
		ATF_CHECK_EQ(1, run_staged_query(connection_queries[i],
		    connection_queries[i][1] != NULL ? 2 : 1,
		    IPC_OP_DOMAIN_GAP, conn, sizeof(conn)));
	{
		static const char *const missing[] = {
			"list", "06:05:04:03:02:01"
		};

		ATF_CHECK_EQ(1, run_staged_query(missing, 2, IPC_OP_DOMAIN_GAP,
		    conn, sizeof(conn)));
	}
	conn[15] = 2; conn[16] = 1;
	ATF_CHECK_EQ(1, run_staged_query(connection_queries[4], 1,
	    IPC_OP_DOMAIN_GAP, conn, sizeof(conn)));

	memset(bonds, 0, sizeof(bonds));
	ipc_put_le16(bonds, IPC_SECURITY_BOND_LIST);
	ipc_put_le16(bonds + 2, 1);
	bonds[4] = 1;
	memcpy(bonds + 5, addr, sizeof(addr));
	bonds[11] = IPC_SECURITY_BOND_F_LTK | IPC_SECURITY_BOND_F_IRK |
	    IPC_SECURITY_BOND_F_CSRK | IPC_SECURITY_BOND_F_SC |
	    IPC_SECURITY_BOND_F_LINK_KEY;
	strlcpy((char *)bonds + 12, "bonded peer", 64);
	ATF_CHECK_EQ(1, run_staged_query(bondsv, 1, IPC_OP_DOMAIN_SECURITY,
	    bonds, sizeof(bonds)));

	memset(resolv, 0, sizeof(resolv));
	ipc_put_le16(resolv, IPC_SECURITY_RESOLV_LIST);
	ipc_put_le16(resolv + 2, 1);
	resolv[4] = 1;
	memcpy(resolv + 5, addr, sizeof(addr));
	resolv[11] = IPC_SECURITY_RESOLV_F_IN_LIST;
	ATF_CHECK_EQ(1, run_staged_query(resolvv, 2, IPC_OP_DOMAIN_SECURITY,
	    resolv, sizeof(resolv)));
}

ATF_TC_WITHOUT_HEAD(cli_bond_export_and_keyboard_callbacks);
ATF_TC_BODY(cli_bond_export_and_keyboard_callbacks, tc)
{
	static const char *const exportv[] = {
		"bond-export", "01:02:03:04:05:06"
	};
	struct kbd_state ks;
	ble_ctx_t *ctx;
	ble_addr_t addr;
	uint8_t body[IPC_SECURITY_BOND_EXPORT_REPLY_HDR_SIZE + 3];
	int input[2], saved_stdin, sp[2];

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ipc_put_le16(body, IPC_SECURITY_BOND_EXPORT);
	ipc_put_le16(body + 2, 3);
	body[4] = 0xaa; body[5] = 0xbb; body[6] = 0xcc;
	stage_cli_frame(sp[1], IPC_OP_DOMAIN_SECURITY, 1, body, sizeof(body));
	ATF_CHECK_EQ(1, handle_typed_command(ctx, nitems(exportv),
	    __DECONST(char **, exportv)));

	memset(&addr, 0, sizeof(addr));
	memset(&ks, 0, sizeof(ks));
	ks.ctx = ctx;
	strlcpy(ks.addr, "00:00:00:00:00:00", sizeof(ks.addr));
	kbd_passkey_display_cb(&addr, 123456, &ks);

	ATF_REQUIRE_EQ(0, pipe(input));
	ATF_REQUIRE_EQ(9, write(input[1], "123456\ny\n", 9));
	close(input[1]);
	saved_stdin = dup(STDIN_FILENO);
	ATF_REQUIRE(saved_stdin >= 0);
	ATF_REQUIRE_EQ(STDIN_FILENO, dup2(input[0], STDIN_FILENO));
	close(input[0]);
	clearerr(stdin);
	kbd_passkey_input_cb(&addr, &ks);
	kbd_numcmp_cb(&addr, 654321, &ks);

	/* EOF is surfaced as an interaction failure for either prompt. */
	clearerr(stdin);
	ks.done = false; ks.ret = EX_OK;
	kbd_passkey_input_cb(&addr, &ks);
	ATF_CHECK(ks.done); ATF_CHECK_EQ(EX_ERR, ks.ret);
	clearerr(stdin);
	ks.done = false; ks.ret = EX_OK;
	kbd_numcmp_cb(&addr, 654321, &ks);
	ATF_CHECK(ks.done); ATF_CHECK_EQ(EX_ERR, ks.ret);
	ATF_REQUIRE_EQ(STDIN_FILENO, dup2(saved_stdin, STDIN_FILENO));
	close(saved_stdin);
	clearerr(stdin);

	/* A vanished daemon turns otherwise-valid prompt replies into explicit
	 * workflow failures. */
	close(sp[1]);
	(void)signal(SIGPIPE, SIG_IGN);
	ATF_REQUIRE_EQ(0, pipe(input));
	ATF_REQUIRE_EQ(9, write(input[1], "123456\ny\n", 9));
	close(input[1]);
	saved_stdin = dup(STDIN_FILENO);
	ATF_REQUIRE(saved_stdin >= 0);
	ATF_REQUIRE_EQ(STDIN_FILENO, dup2(input[0], STDIN_FILENO));
	close(input[0]);
	clearerr(stdin);
	ks.done = false; ks.ret = EX_OK;
	kbd_passkey_input_cb(&addr, &ks);
	ATF_CHECK(ks.done); ATF_CHECK_EQ(EX_ERR, ks.ret);
	kbd_numcmp_cb(&addr, 654321, &ks);
	ATF_CHECK(ks.done); ATF_CHECK_EQ(EX_ERR, ks.ret);
	ATF_REQUIRE_EQ(STDIN_FILENO, dup2(saved_stdin, STDIN_FILENO));
	close(saved_stdin);
	clearerr(stdin);
	ble_close(ctx);
}

ATF_TC_WITHOUT_HEAD(cli_wait_and_sandbox_matrix);
ATF_TC_BODY(cli_wait_and_sandbox_matrix, tc)
{
	struct typed_wait wait = { .done = true, .status = 7 };
	ble_ctx_t *ctx;
	uint16_t handle = 1;
	pid_t child;
	int sp[2], status;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	got_sigint = 0;
	ATF_CHECK_EQ(0, wait_typed_handle(ctx, &handle));
	ATF_CHECK_EQ(7, wait_typed_result(ctx, &wait));
	handle = 0;
	wait.done = false;
	close(sp[1]);
	ATF_CHECK_EQ(-1, wait_typed_handle(ctx, &handle));
	ATF_CHECK_EQ(-1, wait_typed_result(ctx, &wait));
	ble_close(ctx);

	ctl_harden_fd(-1);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		const char *profile;
		FILE *profile_file = NULL;
		int pair[2];

		if (__llvm_profile_set_file_object != NULL &&
		    __llvm_profile_write_file != NULL &&
		    (profile = getenv("LLVM_PROFILE_FILE")) != NULL) {
			/* The destination must be opened before cap_enter().  Keeping
			 * the pattern literal gives this child a separate raw profile. */
			profile_file = fopen(profile, "w+b");
			if (profile_file == NULL ||
			    __llvm_profile_set_file_object(profile_file, 0) != 0)
				_exit(3);
		}
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
			_exit(2);
		ctl_sandbox(pair[0]);
		if (profile_file != NULL && __llvm_profile_write_file() != 0)
			_exit(4);
		if (profile_file != NULL)
			(void)fclose(profile_file);
		_exit(0);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

static int
run_interactive_sequence(ble_ctx_t *ctx)
{
	static const char *const lines[] = {
		"\n", "help\n", "find bad-address\n", "list bad-address\n",
		"connect bad-address\n", "unknown-command\n", "quit\n"
	};
	pid_t child;
	int pfd[2], saved, status, rc;

	ATF_REQUIRE_EQ(0, pipe(pfd));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(pfd[0]);
		for (size_t i = 0; i < nitems(lines); i++) {
			(void)write(pfd[1], lines[i], strlen(lines[i]));
			usleep(10000);
		}
		close(pfd[1]);
		_exit(0);
	}
	close(pfd[1]);
	saved = dup(STDIN_FILENO);
	ATF_REQUIRE(saved >= 0);
	ATF_REQUIRE_EQ(STDIN_FILENO, dup2(pfd[0], STDIN_FILENO));
	close(pfd[0]);
	(void)setvbuf(stdin, NULL, _IONBF, 0);
	clearerr(stdin);
	got_sigint = 0;
	rc = interactive_mode(ctx);
	ATF_REQUIRE_EQ(STDIN_FILENO, dup2(saved, STDIN_FILENO));
	close(saved);
	clearerr(stdin);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (rc);
}

ATF_TC_WITHOUT_HEAD(cli_interactive_and_modes_matrix);
ATF_TC_BODY(cli_interactive_and_modes_matrix, tc)
{
	struct serve_state ss;
	ble_ctx_t *ctx;
	ble_addr_t addr;
	uint8_t value[] = { 1, 2, 3 };
	char scan[] = "scan", find[] = "find";
	char peer[] = "01:02:03:04:05:06", bad[] = "bad-address";
	char *scanv[] = { scan }, *findv[] = { find, peer };
	pid_t child;
	int sp[2], status;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));
	ctx = ble_open_fd(sp[0]);
	ATF_REQUIRE(ctx != NULL);
	ATF_CHECK_EQ(1, run_interactive_sequence(ctx));

	/* Callback-backed serve paths, including matching and rejecting reads. */
	memset(&ss, 0, sizeof(ss));
	ss.ctx = ctx; ss.handle = 0x20; ss.vlen = sizeof(value);
	memcpy(ss.value, value, sizeof(value));
	serve_read_cb(0x20, 0, &ss);
	serve_read_cb(0x21, 1, &ss);
	memset(&addr, 0, sizeof(addr));
	serve_authorize_cb(&addr, 0x20, false, &ss);
	serve_authorize_cb(&addr, 0x20, true, &ss);
	ATF_CHECK_EQ(EX_USAGE, serve_mode(ctx, "not-a-handle", "00"));
	ATF_CHECK_EQ(EX_USAGE, serve_mode(ctx, "20", "0"));
	ATF_CHECK_EQ(EX_USAGE, keyboard_flow(ctx, "bad-address"));
	ATF_CHECK_EQ(1, run_profile_read(ctx, bad, BLE_SVC_BATTERY,
	    BLE_CHR_BATTERY_LEVEL));
	ATF_CHECK_EQ(1, handle_profile_cmd(ctx, 2, findv));

	/* Pre-signalled modes exercise their orderly completion paths without
	 * waiting for external Bluetooth activity. */
	got_sigint = 1;
	ATF_CHECK_EQ(1, handle_typed_command(ctx, 1, scanv));
	ATF_CHECK_EQ(EX_OK, monitor_mode(ctx));
	ATF_CHECK_EQ(EX_OK, serve_mode(ctx, "20", "0102"));
	ATF_CHECK_EQ(EX_TIMEOUT, keyboard_flow(ctx, peer));
	got_sigint = 0;

	/* Closed daemon exercises monitor/serve disconnect handling immediately. */
	close(sp[1]);
	(void)signal(SIGPIPE, SIG_IGN);
	got_sigint = 0;
	ATF_CHECK_EQ(EX_ERR, monitor_mode(ctx));
	got_sigint = 0;
	ATF_CHECK_EQ(EX_ERR, serve_mode(ctx, "20", "0102"));
	ble_close(ctx);

	/* usage() deliberately exits; isolate it and assert its contract. */
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		usage();
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(1, WEXITSTATUS(status));

	/* Both main-level usage routes are contracts in their own right. */
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		char prog[] = "bluedctl", invalid[] = "-z";
		char *argv[] = { prog, invalid };

		optind = 1;
		optreset = 1;
		(void)bluedctl_main_unused(2, argv);
		_exit(99);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(1, WEXITSTATUS(status));

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		char prog[] = "bluedctl";
		char *argv[] = { prog };

		optind = 1;
		optreset = 1;
		(void)bluedctl_main_unused(1, argv);
		_exit(99);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(1, WEXITSTATUS(status));
}

static void
mock_read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	ssize_t n;

	while (len != 0) {
		n = recv(fd, p, len, 0);
		ATF_REQUIRE(n > 0);
		p += n;
		len -= (size_t)n;
	}
}

static unsigned mock_main_sequence;

static int
run_main_with_mock(int argc, char **argv, bool empty_stdin)
{
	struct sockaddr_un sun;
	uint8_t header[IPC_HDR_SIZE], payload[IPC_MAX_PAYLOAD], features[4];
	uint32_t len;
	uint16_t type, arg;
	char path[sizeof(sun.sun_path)];
	pid_t child;
	int client_fd, devnull, listen_fd, status;

	snprintf(path, sizeof(path), "/tmp/bluedctl-main-%d-%u.sock",
	    (int)getpid(), ++mock_main_sequence);
	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ATF_REQUIRE(listen_fd >= 0);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	(void)unlink(path);
	ATF_REQUIRE_EQ(0, bind(listen_fd, (struct sockaddr *)&sun, sizeof(sun)));
	ATF_REQUIRE_EQ(0, listen(listen_fd, 1));
	argv[2] = path;

	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(listen_fd);
		(void)signal(SIGPIPE, SIG_IGN);
		ctl_sandbox_enabled = false;
		if (empty_stdin) {
			devnull = open("/dev/null", O_RDONLY);
			if (devnull >= 0) {
				(void)dup2(devnull, STDIN_FILENO);
				close(devnull);
			}
		}
		optind = 1;
		optreset = 1;
		exit(bluedctl_main_unused(argc, argv));
	}
	client_fd = accept(listen_fd, NULL, NULL);
	ATF_REQUIRE(client_fd >= 0);
	ipc_put_le32(features, IPC_FEATURE_EVENTS | IPC_FEATURE_FDPASS |
	    IPC_FEATURE_MESH);
	ipc_hdr_encode(header, sizeof(features), IPC_T_HELLO,
	    IPC_PROTO_VERSION);
	ATF_REQUIRE_EQ((ssize_t)sizeof(header), send(client_fd, header,
	    sizeof(header), 0));
	ATF_REQUIRE_EQ((ssize_t)sizeof(features), send(client_fd, features,
	    sizeof(features), 0));
	mock_read_all(client_fd, header, sizeof(header));
	ipc_hdr_decode(header, &len, &type, &arg);
	ATF_REQUIRE(len <= sizeof(payload));
	mock_read_all(client_fd, payload, len);
	ATF_CHECK_EQ(IPC_T_HELLO, type);
	ATF_CHECK_EQ(IPC_PROTO_VERSION, arg);
	close(client_fd);
	close(listen_fd);
	(void)unlink(path);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	return (WEXITSTATUS(status));
}

ATF_TC_WITHOUT_HEAD(cli_main_routing_matrix);
ATF_TC_BODY(cli_main_routing_matrix, tc)
{
	char prog[] = "bluedctl", sockopt[] = "-s", placeholder[] = "";
	char json[] = "-j", help[] = "help";
	char unknown[] = "unknown", serve[] = "serve", scan[] = "scan";
	char status[] = "status", battery[] = "battery";
	char keyboard[] = "keyboard", monitor[] = "monitor", interactive[] = "-i";
	char addr[] = "01:02:03:04:05:06";
	char *unknownv[] = { prog, sockopt, placeholder, unknown };
	char *servev[] = { prog, sockopt, placeholder, serve };
	char handle[] = "20", hex[] = "0102";
	char missing[] = "/nonexistent/blued.sock";
	char *servefullv[] = { prog, sockopt, placeholder, serve, handle, hex };
	char *missingv[] = { prog, sockopt, missing, status };
	char *scanv[] = { prog, sockopt, placeholder, scan };
	char *statusv[] = { prog, sockopt, placeholder, status };
	char *batteryv[] = { prog, sockopt, placeholder, battery, addr };
	char *keyboardv[] = { prog, sockopt, placeholder, keyboard, addr };
	char *monitorv[] = { prog, sockopt, placeholder, monitor };
	char *interactivev[] = { prog, sockopt, placeholder, interactive };
	char *jsonhelpv[] = { prog, json, help };

	optind = 1; optreset = 1; json_mode = false;
	ATF_CHECK_EQ(EX_OK, bluedctl_main_unused(3, jsonhelpv));
	ATF_CHECK(json_mode);

	ATF_CHECK_EQ(EX_USAGE, run_main_with_mock(4, unknownv, false));
	ATF_CHECK_EQ(EX_USAGE, run_main_with_mock(4, servev, false));
	ATF_CHECK_EQ(EX_ERR, run_main_with_mock(6, servefullv, false));
	ATF_CHECK(run_main_with_mock(4, scanv, false) != EX_OK);
	ATF_CHECK(run_main_with_mock(4, statusv, false) != EX_OK);
	ATF_CHECK(run_main_with_mock(5, batteryv, false) != EX_OK);
	ATF_CHECK(run_main_with_mock(5, keyboardv, false) != EX_OK);
	ATF_CHECK(run_main_with_mock(4, monitorv, false) != EX_OK);
	(void)run_main_with_mock(4, interactivev, true);
	optind = 1; optreset = 1;
	ATF_CHECK_EQ(1, bluedctl_main_unused(4, missingv));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, k1_join_args_canary);
	ATF_TP_ADD_TC(tp, k1_join_args_fits);
	ATF_TP_ADD_TC(tp, cli_pure_helper_matrix);
	ATF_TP_ADD_TC(tp, cli_callback_and_help_matrix);
	ATF_TP_ADD_TC(tp, cli_workflow_helper_matrix);
	ATF_TP_ADD_TC(tp, cli_typed_dispatch_matrix);
	ATF_TP_ADD_TC(tp, cli_typed_success_matrix);
	ATF_TP_ADD_TC(tp, cli_query_profile_help_matrix);
	ATF_TP_ADD_TC(tp, cli_query_success_matrix);
	ATF_TP_ADD_TC(tp, cli_bond_export_and_keyboard_callbacks);
	ATF_TP_ADD_TC(tp, cli_wait_and_sandbox_matrix);
	ATF_TP_ADD_TC(tp, cli_interactive_and_modes_matrix);
	ATF_TP_ADD_TC(tp, cli_main_routing_matrix);
	return (atf_no_error());
}
