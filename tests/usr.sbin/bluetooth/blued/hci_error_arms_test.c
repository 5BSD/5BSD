/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Error-arm / failure-path branch coverage for the blued HCI host encoders.
 *
 * The wrap-seam tests hci_devreq_mock_test.c and power_control_deep_test.c
 * already drive the happy path and the controller-rejection (rp.status != 0)
 * arm of the encoders that reach the controller through bt_devreq().  This
 * file closes the remaining measured gaps toward full branch coverage:
 *
 *   1. The verbose-gated LOG_HCI/LOG_L2C trace regions of *every* encoder
 *      (blued_verbose >= 1, and both the fprintf and syslog daemonized arms):
 *      with the default blued_verbose == 0 these regions never execute, which
 *      is the ~50% uniform branch floor seen across the LE encoders.
 *
 *   2. The scanning orchestration functions hci_le_scan() / hci_le_ext_scan()
 *      and the report de-duplication merge (scan_result_merge): success with
 *      report parsing + merge, the controller-rejection arms of every setup
 *      command, the 0x0C "conflicting state" retry path, and the malformed /
 *      truncated / timeout report arms.  Driven by wrapping bt_devrecv (feed
 *      advertising / meta events) and bt_devfilter (no-op).
 *
 *   3. The L2CAP CoC / ECBFC connect encoders (ble_coc_connect,
 *      ble_ecbfc_connect, ble_ecbfc_reconfig) — success and every socket-layer
 *      failure arm — driven by wrapping socket/bind/connect/setsockopt/close
 *      (fault injection at the syscall seam; the encoders perform no heap
 *      allocation, so there is no malloc arm to inject).
 *
 *   4. hci_wait_encryption(): success, controller-fail (status/enable), the
 *      handle-mismatch, short-event, EAGAIN-continue, recv-error-break, and
 *      timeout arms.
 *
 *   5. hci_util.c: hci_get_con_handle (found / not-found / link-type /
 *      ioctl-fail, wrapping ioctl), hci_disconnect (all three post-I/O arms),
 *      hci_send_raw_cmd, and l2cap_conn_param_update_req (adapter scan +
 *      con-handle lookup, wrapping bt_devopen).
 *
 *   6. Every pre-I/O parameter-validation reject arm (errno == EINVAL) across
 *      the encoders (Core Spec Vol 4 Part E §7.8 range rules).
 *
 *   7. The BTSnoop command/response logging branches of hci_devreq_logged_locked
 *      (hci_log_enabled() true) for both Command Complete and Command Status.
 *
 * SPEC ORACLE: every asserted error is the spec-mandated mapping
 *   - controller status != 0x00           -> -1 / EIO   (Core Spec Vol 4 Part E
 *     §7.5-7.8 "the Command Complete/Status carries a Status parameter";
 *     blued maps any non-zero Status to EIO)
 *   - out-of-range command parameter       -> -1 / EINVAL (the §7.8 range rules)
 *   - transport failure (bt_devreq < 0)     -> -1 (errno from the transport)
 * asserted values are hand-derived from the spec, never captured from output.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <atf-c.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_btsocket.h>

#include "hci_util.h"
#include "hci_internal.h"
#include "hci_log.h"
#include "ble_util.h"
#include "spec_oracles.h"

/* Stub globals required by the hci_*.c logging macros. */
atomic_int blued_verbose = 0;
int blued_daemonized = 0;

#define FD	3

/* ================================================================
 * bt_devreq seam.  Two modes:
 *   simple  — one controlled response (status byte + optional read params)
 *   seq     — per-call script for the multi-command scan flows
 * ================================================================ */
static struct {
	int		ncalls;
	/* simple mode */
	int		fail;
	int		fail_errno;
	uint8_t		payload[320];
	size_t		payload_len;
	/* sequence mode */
	int		use_seq;
	int		seq_len;
	uint8_t		seq_status[12];
	int		seq_fail[12];
} R;

int __wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);
ssize_t __wrap_bt_devrecv(int s, void *buf, size_t size, time_t to);
int __wrap_bt_devfilter(int s, struct bt_devfilter const *nw,
    struct bt_devfilter *old);
int __wrap_bt_devopen(char const *devname);

int
__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to)
{
	int idx = R.ncalls++;

	(void)s;
	(void)to;

	if (R.use_seq && idx < R.seq_len) {
		if (R.seq_fail[idx]) {
			errno = EIO;
			return (-1);
		}
		if (r->rparam != NULL && r->rlen > 0) {
			memset(r->rparam, 0, r->rlen);
			*((uint8_t *)r->rparam) = R.seq_status[idx];
		}
		return (0);
	}

	if (R.fail) {
		errno = R.fail_errno;
		return (-1);
	}
	if (r->rparam != NULL && r->rlen > 0) {
		size_t n = R.payload_len < r->rlen ? R.payload_len : r->rlen;

		memset(r->rparam, 0, r->rlen);
		if (n > 0)
			memcpy(r->rparam, R.payload, n);
	}
	return (0);
}

static void
mock_ok(void)
{
	uint8_t st = 0x00;

	memset(&R, 0, sizeof(R));
	R.payload[0] = st;
	R.payload_len = 1;
}

static void
mock_ok_bytes(const void *p, size_t n)
{
	memset(&R, 0, sizeof(R));
	if (n > sizeof(R.payload))
		n = sizeof(R.payload);
	memcpy(R.payload, p, n);
	R.payload_len = n;
}

static void
mock_status_bad(void)
{
	memset(&R, 0, sizeof(R));
	R.payload[0] = 0x0C;		/* Command Disallowed */
	R.payload_len = 1;
}

static void
mock_xport_fail(int e)
{
	memset(&R, 0, sizeof(R));
	R.fail = 1;
	R.fail_errno = e;
}

/* ================================================================
 * bt_devrecv seam — a scripted queue of receive actions.
 * ================================================================ */
struct recv_action {
	int		is_err;
	int		err;
	uint8_t		buf[300];
	int		len;
};
static struct recv_action Recvq[48];
static int Recvq_len, Recvq_idx;

static void
recv_reset(void)
{
	Recvq_len = 0;
	Recvq_idx = 0;
	memset(Recvq, 0, sizeof(Recvq));
}

static void
recv_push_data(const uint8_t *b, int len)
{
	struct recv_action *a = &Recvq[Recvq_len++];

	a->is_err = 0;
	if (len > (int)sizeof(a->buf))
		len = sizeof(a->buf);
	memcpy(a->buf, b, len);
	a->len = len;
}

static void
recv_push_err(int e)
{
	struct recv_action *a = &Recvq[Recvq_len++];

	a->is_err = 1;
	a->err = e;
}

static int Recv_eagain_forever = 0;	/* when set, always return EAGAIN */

ssize_t
__wrap_bt_devrecv(int s, void *buf, size_t size, time_t to)
{
	struct recv_action *a;

	(void)s;
	(void)to;
	if (Recv_eagain_forever) {
		errno = EAGAIN;
		return (-1);
	}
	if (Recvq_idx >= Recvq_len) {
		/* Nothing scripted left: terminate the caller's loop. */
		errno = EIO;
		return (-1);
	}
	a = &Recvq[Recvq_idx++];
	if (a->is_err) {
		errno = a->err;
		return (-1);
	}
	if ((size_t)a->len > size)
		a->len = size;
	memcpy(buf, a->buf, a->len);
	return (a->len);
}

int
__wrap_bt_devfilter(int s, struct bt_devfilter const *nw, struct bt_devfilter *old)
{
	(void)s;
	(void)nw;
	if (old != NULL)
		memset(old, 0, sizeof(*old));
	return (0);
}

/* bt_devopen seam for l2cap_conn_param_update_req's adapter scan. */
static int G_devopen_fd = -1;		/* fd to hand back, or -1 to fail */
int
__wrap_bt_devopen(char const *devname)
{
	(void)devname;
	if (G_devopen_fd < 0) {
		errno = ENXIO;
		return (-1);
	}
	return (G_devopen_fd);
}

/* ================================================================
 * ioctl seam — only SIOC_HCI_RAW_NODE_GET_CON_LIST is intercepted.
 * ================================================================ */
static int G_ioctl_fail = 0;
static int G_con_count = 0;
static ng_hci_node_con_ep G_cons[8];

int __wrap_ioctl(int fd, unsigned long req, ...);
extern int __real_ioctl(int fd, unsigned long req, ...);

int
__wrap_ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);

	if (req == SIOC_HCI_RAW_NODE_INIT) {
		if (G_ioctl_fail) {
			errno = EPERM;
			return (-1);
		}
		return (0);
	}
	if (req == SIOC_HCI_RAW_NODE_GET_CON_LIST) {
		struct ng_btsocket_hci_raw_con_list *cl = arg;
		int i;

		if (G_ioctl_fail) {
			errno = EPERM;
			return (-1);
		}
		if (cl->connections != NULL) {
			for (i = 0; i < G_con_count &&
			    (uint32_t)i < cl->num_connections; i++)
				cl->connections[i] = G_cons[i];
		}
		cl->num_connections = G_con_count;
		return (0);
	}
	return (__real_ioctl(fd, req, arg));
}

/* ================================================================
 * socket-layer seams for the CoC / ECBFC encoders.  Only Bluetooth
 * sockets (and the fake fds they hand out, >= FAKEFD_BASE) are
 * intercepted; everything else delegates to the real libc call so
 * the ATF runtime is unaffected.
 * ================================================================ */
#define FAKEFD_BASE	700

static int G_sock_fail = 0;		/* socket() returns -1 */
static int G_bind_fail = 0;		/* bind() returns -1   */
static int G_connect_fail = 0;		/* connect() returns -1 */
static int G_ecbfc_opt_fail = 0;	/* setsockopt(SO_L2CAP_ECBFC) -1 */
static int G_reconfig_fail = 0;		/* setsockopt(SO_L2CAP_RECONFIG) -1 */
static int G_next_fakefd = FAKEFD_BASE;

int __wrap_socket(int domain, int type, int protocol);
int __wrap_bind(int fd, const struct sockaddr *sa, socklen_t len);
int __wrap_connect(int fd, const struct sockaddr *sa, socklen_t len);
int __wrap_setsockopt(int fd, int level, int name, const void *val,
    socklen_t len);
int __wrap_close(int fd);
extern int __real_socket(int, int, int);
extern int __real_bind(int, const struct sockaddr *, socklen_t);
extern int __real_connect(int, const struct sockaddr *, socklen_t);
extern int __real_setsockopt(int, int, int, const void *, socklen_t);
extern int __real_close(int);

int
__wrap_socket(int domain, int type, int protocol)
{
	if (domain == PF_BLUETOOTH) {
		if (G_sock_fail) {
			errno = EAFNOSUPPORT;
			return (-1);
		}
		return (G_next_fakefd++);
	}
	return (__real_socket(domain, type, protocol));
}

int
__wrap_bind(int fd, const struct sockaddr *sa, socklen_t len)
{
	if (fd >= FAKEFD_BASE) {
		if (G_bind_fail) {
			errno = EADDRINUSE;
			return (-1);
		}
		return (0);
	}
	return (__real_bind(fd, sa, len));
}

int
__wrap_connect(int fd, const struct sockaddr *sa, socklen_t len)
{
	if (fd >= FAKEFD_BASE) {
		if (G_connect_fail) {
			errno = ECONNREFUSED;
			return (-1);
		}
		return (0);
	}
	return (__real_connect(fd, sa, len));
}

int
__wrap_setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
	if (fd >= FAKEFD_BASE) {
		if (name == SO_L2CAP_ECBFC && G_ecbfc_opt_fail) {
			errno = ENOPROTOOPT;
			return (-1);
		}
		if (name == SO_L2CAP_RECONFIG && G_reconfig_fail) {
			errno = EINVAL;
			return (-1);
		}
		return (0);
	}
	return (__real_setsockopt(fd, level, name, val, len));
}

int
__wrap_close(int fd)
{
	if (fd >= FAKEFD_BASE)
		return (0);
	return (__real_close(fd));
}

static void
sock_reset(void)
{
	G_sock_fail = G_bind_fail = G_connect_fail = 0;
	G_ecbfc_opt_fail = G_reconfig_fail = 0;
	G_next_fakefd = FAKEFD_BASE;
}

/* ================================================================
 * write()/writev() seams — one-shot fault injection for the BTSnoop
 * logger's "write failed / short write, closing" arms in hci_log.c.
 * 0 = pass through to libc; 1 = fail (-1); 2 = short write.
 * ================================================================ */
static int G_writev_fault = 0;
static int G_write_fault = 0;

ssize_t __wrap_writev(int fd, const struct iovec *iov, int cnt);
ssize_t __wrap_write(int fd, const void *buf, size_t n);
extern ssize_t __real_writev(int, const struct iovec *, int);
extern ssize_t __real_write(int, const void *, size_t);

ssize_t
__wrap_writev(int fd, const struct iovec *iov, int cnt)
{
	if (G_writev_fault == 1) {
		G_writev_fault = 0;
		errno = EIO;
		return (-1);
	}
	if (G_writev_fault == 2) {
		G_writev_fault = 0;
		return (1);			/* short write */
	}
	return (__real_writev(fd, iov, cnt));
}

ssize_t
__wrap_write(int fd, const void *buf, size_t n)
{
	if (G_write_fault == 1) {
		G_write_fault = 0;
		return (1);			/* short write of the BTSnoop hdr */
	}
	return (__real_write(fd, buf, n));
}

/* ================================================================
 * Encoder inventory — one call of every controller-bound encoder with
 * valid parameters.  Used by the verbose-logging sweep to reach the
 * success/failure trace regions of each command; the controller
 * response is whatever the caller mocked beforehand.
 * ================================================================ */
static void
call_all_encoders(void)
{
	uint8_t data[8] = { 0x02, 0x01, 0x06 };
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t irk[16], ltk[16], bcode[16];
	uint8_t ant[2] = { 0, 1 };
	uint8_t bis[1] = { 1 };
	uint8_t codec_id[5] = { 0x03, 0, 0, 0, 0 };
	uint8_t phy_params[16];
	uint8_t cis_params[9];
	uint16_t cis_h[1] = { 0x0100 };
	uint16_t acl_h[1] = { 0x0001 };
	uint16_t handles[1] = { 0 };
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t max_len = 0, u16 = 0;
	uint8_t u8a = 0, u8b = 0, u8c = 0, u8d = 0;
	uint64_t u64 = 0;
	uint32_t u32a = 0, u32b = 0, u32c = 0, u32d = 0, u32e = 0, u32f = 0,
	    u32g = 0;
	int8_t i8a = 0, i8b = 0;
	uint8_t bd[6];

	memset(irk, 0xA5, sizeof(irk));
	memset(ltk, 0x5A, sizeof(ltk));
	memset(bcode, 0, sizeof(bcode));
	memset(phy_params, 0, sizeof(phy_params));
	memset(cis_params, 0, sizeof(cis_params));

	/* hci_util.c */
	(void)hci_get_bdaddr(FD, bd);

	/* hci_adv.c — legacy + extended + periodic + PAST + CTE */
	(void)hci_le_set_advertising_params(FD, 0x0020, 0x0040, 0, 0, 0);
	(void)hci_le_set_advertising_data(FD, data, 3);
	(void)hci_le_set_scan_response_data(FD, data, 3);
	(void)hci_le_set_advertise_enable(FD, true);
	(void)hci_le_set_advertise_enable(FD, false);
	(void)hci_le_set_ext_adv_params_phy(FD, 0, 0x0013, 0x000020, 0x000040,
	    0, 0, 1, 1);
	(void)hci_le_set_ext_adv_params(FD, 0, 0x0013, 0x000020, 0x000040, 0, 0);
	(void)hci_le_set_ext_adv_data(FD, 0, data, 3);
	(void)hci_le_set_ext_adv_enable(FD, 1, 0);
	(void)hci_le_remove_adv_set(FD, 0);
	(void)hci_le_set_adv_set_random_address(FD, 0, addr);
	(void)hci_le_set_ext_scan_response_data(FD, 0, data, 3);
	(void)hci_le_read_max_adv_data_length(FD, &max_len);
	(void)hci_le_read_num_supported_adv_sets(FD, &u8a);
	(void)hci_le_clear_adv_sets(FD);
	(void)hci_le_set_periodic_adv_params(FD, 0, 0x0006, 0x0006, 0);
	(void)hci_le_set_periodic_adv_data(FD, 0, data, 3);
	(void)hci_le_set_periodic_adv_enable(FD, 1, 0);
	(void)hci_le_periodic_adv_create_sync(FD, 0, 0, 0, addr, 0, 0x000A);
	(void)hci_le_periodic_adv_create_sync_cancel(FD);
	(void)hci_le_periodic_adv_terminate_sync(FD, 0x0001);
	(void)hci_le_add_dev_to_periodic_adv_list(FD, 0, addr, 0);
	(void)hci_le_remove_dev_from_periodic_adv_list(FD, 0, addr, 0);
	(void)hci_le_clear_periodic_adv_list(FD);
	(void)hci_le_read_periodic_adv_list_size(FD, &u8a);
	(void)hci_le_set_periodic_adv_receive_enable(FD, 0x0001, 1);
	(void)hci_le_periodic_adv_sync_transfer(FD, 0x0001, 0x1234, 0x0001);
	(void)hci_le_periodic_adv_set_info_transfer(FD, 0x0001, 0x1234, 0);
	(void)hci_le_set_past_params(FD, 0x0001, 0, 0, 0x000A, 0);
	(void)hci_le_set_default_past_params(FD, 0, 0, 0x000A, 0);
	(void)hci_le_set_connless_cte_tx_params(FD, 0, 0x14, 0, 1, 2, ant);
	(void)hci_le_set_connless_cte_tx_enable(FD, 0, 1);
	(void)hci_le_set_connless_iq_sampling_enable(FD, 0x0001, 1, 1, 0, 2, ant);
	(void)hci_le_set_conn_cte_rx_params(FD, 0x0001, 1, 1, 2, ant);
	(void)hci_le_set_conn_cte_tx_params(FD, 0x0001, 0x01, 2, ant);
	(void)hci_le_conn_cte_req_enable(FD, 0x0001, 1, 0x000A, 0x14, 0);
	(void)hci_le_conn_cte_rsp_enable(FD, 0x0001, 1);
	(void)hci_le_read_antenna_info(FD, &u8a, &u8b, &u8c, &u8d);

	/* hci_conn.c */
	(void)hci_le_connection_update(FD, 0x0040, 0x0006, 0x0006, 0, 0x000A);
	(void)hci_le_set_data_length(FD, 0x0040, 0x001B, 0x0148);
	(void)hci_le_write_suggested_default_data_length(FD, 0x001B, 0x0148);
	(void)hci_le_set_default_phy(FD, 0, 0x07, 0x07);
	(void)hci_le_set_phy(FD, 0x0040, 0, 0x07, 0x07, 0);
	(void)hci_le_read_phy(FD, 0x0040, &u8a, &u8b);
	(void)hci_le_set_host_feature(FD, 32, 1);
	(void)hci_le_create_connection_cancel(FD);
	(void)hci_le_set_default_subrate(FD, 1, 4, 0, 0, 0x000A);
	(void)hci_le_subrate_request(FD, 0x0040, 1, 4, 0, 0, 0x000A);
	(void)hci_le_enhanced_read_tx_power_level(FD, 0x0040, 1, &i8a, &i8b);
	(void)hci_le_read_remote_tx_power_level(FD, 0x0040, 1);
	(void)hci_le_set_path_loss_reporting_params(FD, 0x0040, 0x40, 0x04,
	    0x10, 0x04, 0x000A);
	(void)hci_le_set_path_loss_reporting_enable(FD, 0x0040, 1);
	(void)hci_le_set_tx_power_reporting_enable(FD, 0x0040, 1, 1);
	(void)hci_le_ext_create_connection(FD, 0, 0, 0, addr, 0x01, phy_params,
	    sizeof(phy_params));

	/* hci_privacy.c */
	(void)hci_le_clear_resolving_list(FD);
	(void)hci_le_add_dev_resolving_list(FD, 0, addr, irk, irk);
	(void)hci_le_set_addr_resolution_enable(FD, 1);
	(void)hci_le_set_privacy_mode(FD, 0, addr, 0);
	(void)hci_le_set_rpa_timeout(FD, 900);
	(void)hci_le_clear_filter_accept_list(FD);
	(void)hci_le_add_device_to_filter_accept_list(FD, 0, addr);
	(void)hci_le_remove_device_from_filter_accept_list(FD, 0, addr);

	/* hci_misc.c */
	(void)hci_reset(FD);
	(void)hci_write_le_host_support(FD, 1, 0);
	(void)hci_set_event_mask(FD, 0x00001FFFFFFFFFFFULL);
	(void)hci_le_read_local_features(FD, &u64);
	(void)hci_le_set_event_mask(FD, 0x1F);
	(void)hci_le_ltk_request_reply(FD, 0x0040, ltk);
	(void)hci_le_ltk_request_neg_reply(FD, 0x0040);
	(void)hci_set_min_enc_key_size(FD, 16);
	(void)hci_le_write_auth_payload_timeout(FD, 0x0040, 0x0BB8);
	(void)hci_le_read_auth_payload_timeout(FD, 0x0040, &u16);
	(void)hci_le_read_buffer_size_v2(FD, &max_len, &u8a, &u16, &u8b);
	(void)hci_le_read_iso_tx_sync(FD, 0x0040, &u16, &u32a, &u32b);
	(void)hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0, 0, 0, 10, 10, 1,
	    cis_params, sizeof(cis_params), &out_cig, &out_cnt, handles);
	(void)hci_le_create_cis(FD, 1, cis_h, acl_h);
	(void)hci_le_remove_cig(FD, 0x05);
	(void)hci_le_accept_cis_request(FD, 0x0040);
	(void)hci_le_reject_cis_request(FD, 0x0040, 0x0D);
	(void)hci_le_create_big(FD, 0, 0, 1, 10000, 100, 10, 0, 0x01, 0, 0, 0,
	    bcode);
	(void)hci_le_terminate_big(FD, 0, 0x16);
	(void)hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0, 0x0064, 1, bis);
	(void)hci_le_big_terminate_sync(FD, 0);
	(void)hci_le_setup_iso_data_path(FD, 0x0040, 0, 0, codec_id, 0, 0, NULL);
	(void)hci_le_remove_iso_data_path(FD, 0x0040, 0x01);
	(void)hci_le_request_peer_sca(FD, 0x0040);
	(void)hci_le_read_iso_link_quality(FD, 0x0040, &u32a, &u32b, &u32c,
	    &u32d, &u32e, &u32f, &u32g);
}

/* ================================================================
 * Verbose-gated trace regions of every encoder.
 *
 * ATF isolates each test case in its own process, so toggling the
 * globals here does not disturb the other cases.  This case exists
 * purely to reach the LOG_HCI regions gated by (blued_verbose >= lvl)
 * and the (blued_daemonized ? syslog : fprintf) sub-branch on both the
 * success trace and the "... failed" trace; behavioural correctness of
 * each command is asserted elsewhere.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(verbose_log_sweep);
ATF_TC_BODY(verbose_log_sweep, tc)
{
	int d;

	blued_verbose = 2;
	for (d = 0; d <= 1; d++) {
		blued_daemonized = d;
		mock_ok();
		call_all_encoders();		/* success traces */
		mock_status_bad();
		call_all_encoders();		/* "... failed" traces */
	}
	blued_verbose = 0;
	blued_daemonized = 0;
	ATF_CHECK(true);
}

/* ================================================================
 * Controller-rejection + transport arm of every encoder.
 *
 * Spec oracle: a Command Complete/Status carrying Status != 0x00 is a
 * command failure; the encoders map it to -1 with errno EIO.  A
 * transport failure (bt_devreq < 0) is propagated as -1.  Asserted on a
 * representative spread; the exhaustive per-command byte-layout oracle
 * lives in hci_devreq_mock_test.c / iso_transport_test.c.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(reject_arm_maps_to_eio);
ATF_TC_BODY(reject_arm_maps_to_eio, tc)
{
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };

	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_advertise_enable(FD, true));
	ATF_CHECK_EQ(EIO, errno);

	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_clear_adv_sets(FD));
	ATF_CHECK_EQ(EIO, errno);

	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_add_device_to_filter_accept_list(FD, 0, addr));
	ATF_CHECK_EQ(EIO, errno);

	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_reset(FD));
	ATF_CHECK_EQ(EIO, errno);

	mock_xport_fail(EIO);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_set_advertise_enable(FD, true));

	mock_xport_fail(ENXIO);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_reset(FD));
}

/* ================================================================
 * Pre-I/O parameter-validation reject arms — errno EINVAL, no I/O.
 * The value ranges are the Core Spec Vol 4 Part E §7.8 rules cited in
 * the encoder source.
 * ================================================================ */
#define REJECT_EINVAL(call)	do {					\
	mock_ok();							\
	errno = 0;							\
	ATF_CHECK_EQ_MSG(-1, (call), "expected -1 (EINVAL reject)");	\
	ATF_CHECK_EQ_MSG(EINVAL, errno, "expected EINVAL");		\
	ATF_CHECK_EQ_MSG(0, R.ncalls, "must reject before I/O");	\
} while (0)

ATF_TC_WITHOUT_HEAD(validation_adv);
ATF_TC_BODY(validation_adv, tc)
{
	uint8_t big[512];

	memset(big, 0, sizeof(big));

	/* §7.8.5 advertising interval 0x0020-0x4000, min<=max. */
	REJECT_EINVAL(hci_le_set_advertising_params(FD, 0x0010, 0x0040, 0, 0, 0));
	REJECT_EINVAL(hci_le_set_advertising_params(FD, 0x0020, 0x8000, 0, 0, 0));
	REJECT_EINVAL(hci_le_set_advertising_params(FD, 0x0100, 0x0040, 0, 0, 0));
	REJECT_EINVAL(hci_le_set_advertising_params(FD, 0x0020, 0x0040, 5, 0, 0));
	REJECT_EINVAL(hci_le_set_advertising_params(FD, 0x0020, 0x0040, 0, 4, 0));
	REJECT_EINVAL(hci_le_set_advertising_params(FD, 0x0020, 0x0040, 0, 0, 4));
	REJECT_EINVAL(hci_le_set_advertising_params_dir(FD, 0x0020, 0x0040,
	    1, 0, 0, 0, NULL));
	REJECT_EINVAL(hci_le_set_advertising_params_dir(FD, 0x0020, 0x0040,
	    1, 0, 0, 2, big));
	/* §7.8.7 advertising data <= 31 octets. */
	REJECT_EINVAL(hci_le_set_advertising_data(FD, big, 32));
	REJECT_EINVAL(hci_le_set_advertising_data(FD, NULL, 1));
	/* §7.8.8 scan response data <= 31 octets. */
	REJECT_EINVAL(hci_le_set_scan_response_data(FD, big, 32));
	REJECT_EINVAL(hci_le_set_scan_response_data(FD, NULL, 1));
	/* §7.8.53 extended primary interval 0x000020-0xFFFFFF, min<=max. */
	REJECT_EINVAL(hci_le_set_ext_adv_params_phy(FD, 0, 0x0013, 0x000010,
	    0x000040, 0, 0, 1, 1));
	REJECT_EINVAL(hci_le_set_ext_adv_params(FD, 0, 0x0013, 0x000040,
	    0x000020, 0, 0));
	REJECT_EINVAL(hci_le_set_ext_adv_params_phy(FD, 0xf0, 0x0013,
	    0x000020, 0x000040, 0, 0, 1, 1));
	REJECT_EINVAL(hci_le_set_ext_adv_params_phy(FD, 0, 0x0013,
	    0x000020, 0x000040, 4, 0, 1, 1));
	REJECT_EINVAL(hci_le_set_ext_adv_params_phy(FD, 0, 0x0013,
	    0x000020, 0x000040, 0, 4, 1, 1));
	REJECT_EINVAL(hci_le_set_ext_adv_params_phy(FD, 0, 0x0013,
	    0x000020, 0x000040, 0, 0, 2, 1));
	REJECT_EINVAL(hci_le_set_ext_adv_params_phy(FD, 0, 0x0013,
	    0x000020, 0x000040, 0, 0, 1, 4));
	REJECT_EINVAL(hci_le_set_ext_adv_params_full(FD, 0, 0x0013,
	    0x000020, 0x000040, 0, 0, 1, 1, 0x07, 21, 0, NULL));
	REJECT_EINVAL(hci_le_set_ext_adv_params_full(FD, 0, 0x0004,
	    0x000020, 0x000040, 0, 0, 1, 1, 0x07, 0x7f, 0, NULL));
	/* §7.8.54 extended advertising data length bound. */
	REJECT_EINVAL(hci_le_set_ext_adv_data(FD, 0xf0, big, 1));
	REJECT_EINVAL(hci_le_set_ext_adv_data(FD, 0, big, 252));
	REJECT_EINVAL(hci_le_set_ext_adv_data(FD, 0, NULL, 1));
	REJECT_EINVAL(hci_le_set_ext_adv_enable(FD, 2, 0));
	REJECT_EINVAL(hci_le_set_ext_adv_enable(FD, 1, 0xf0));
	REJECT_EINVAL(hci_le_remove_adv_set(FD, 0xf0));
	REJECT_EINVAL(hci_le_set_adv_set_random_address(FD, 0xf0, big));
	REJECT_EINVAL(hci_le_set_adv_set_random_address(FD, 0, NULL));
	REJECT_EINVAL(hci_le_set_ext_scan_response_data(FD, 0xf0, big, 1));
	REJECT_EINVAL(hci_le_set_ext_scan_response_data(FD, 0, big, 252));
	REJECT_EINVAL(hci_le_set_ext_scan_response_data(FD, 0, NULL, 1));
	/* §7.8.61 periodic advertising interval 0x0006-0xFFFF, min<=max. */
	REJECT_EINVAL(hci_le_set_periodic_adv_params(FD, 0xf0, 0x0006,
	    0x0006, 0));
	REJECT_EINVAL(hci_le_set_periodic_adv_params(FD, 0, 0x0002, 0x0006, 0));
	REJECT_EINVAL(hci_le_set_periodic_adv_params(FD, 0, 0x0008, 0x0006, 0));
	REJECT_EINVAL(hci_le_set_periodic_adv_params(FD, 0, 0x0006, 0x0006, 1));
	REJECT_EINVAL(hci_le_set_periodic_adv_params(FD, 0, 0x0006, 0x0006, 2));
	/* §7.8.62 periodic advertising data length bound. */
	REJECT_EINVAL(hci_le_set_periodic_adv_data(FD, 0xf0, big, 1));
	REJECT_EINVAL(hci_le_set_periodic_adv_data(FD, 0, big, 253));
	REJECT_EINVAL(hci_le_set_periodic_adv_data(FD, 0, NULL, 1));
	REJECT_EINVAL(hci_le_set_periodic_adv_enable(FD, 2, 0));
	REJECT_EINVAL(hci_le_set_periodic_adv_enable(FD, 1, 0xf0));
	/* §7.8.67-.73 periodic sync/list reserved values. */
	REJECT_EINVAL(hci_le_periodic_adv_create_sync(FD, 0x08, 0, 0, big,
	    0, 0x000A));
	REJECT_EINVAL(hci_le_periodic_adv_create_sync(FD, 0, 0x10, 0, big,
	    0, 0x000A));
	REJECT_EINVAL(hci_le_periodic_adv_create_sync(FD, 0, 0, 2, big,
	    0, 0x000A));
	REJECT_EINVAL(hci_le_periodic_adv_create_sync(FD, 0, 0, 0, NULL,
	    0, 0x000A));
	REJECT_EINVAL(hci_le_periodic_adv_create_sync(FD, 0, 0, 0, big,
	    0x01f4, 0x000A));
	REJECT_EINVAL(hci_le_periodic_adv_create_sync(FD, 0, 0, 0, big,
	    0, 0x0009));
	REJECT_EINVAL(hci_le_periodic_adv_terminate_sync(FD, 0x0f00));
	REJECT_EINVAL(hci_le_add_dev_to_periodic_adv_list(FD, 2, big, 0));
	REJECT_EINVAL(hci_le_add_dev_to_periodic_adv_list(FD, 0, NULL, 0));
	REJECT_EINVAL(hci_le_add_dev_to_periodic_adv_list(FD, 0, big, 0x10));
	REJECT_EINVAL(hci_le_remove_dev_from_periodic_adv_list(FD, 2, big, 0));
	REJECT_EINVAL(hci_le_remove_dev_from_periodic_adv_list(FD, 0, NULL, 0));
	REJECT_EINVAL(hci_le_remove_dev_from_periodic_adv_list(FD, 0, big, 0x10));
	/* §7.8.88-.92 PAST handle/range/bitmask validation. */
	REJECT_EINVAL(hci_le_set_periodic_adv_receive_enable(FD, 0x0f00, 1));
	REJECT_EINVAL(hci_le_set_periodic_adv_receive_enable(FD, 0, 2));
	REJECT_EINVAL(hci_le_periodic_adv_sync_transfer(FD, 0x0f00, 0, 0));
	REJECT_EINVAL(hci_le_periodic_adv_sync_transfer(FD, 0, 0, 0x0f00));
	REJECT_EINVAL(hci_le_periodic_adv_set_info_transfer(FD, 0x0f00, 0, 0));
	REJECT_EINVAL(hci_le_periodic_adv_set_info_transfer(FD, 0, 0, 0xf0));
	REJECT_EINVAL(hci_le_set_past_params(FD, 0x0f00, 0, 0, 0x000A, 0));
	REJECT_EINVAL(hci_le_set_past_params(FD, 0, 4, 0, 0x000A, 0));
	REJECT_EINVAL(hci_le_set_past_params(FD, 0, 0, 0x01f4, 0x000A, 0));
	REJECT_EINVAL(hci_le_set_past_params(FD, 0, 0, 0, 0x0009, 0));
	REJECT_EINVAL(hci_le_set_past_params(FD, 0, 0, 0, 0x000A, 0x08));
	REJECT_EINVAL(hci_le_set_default_past_params(FD, 4, 0, 0x000A, 0));
	REJECT_EINVAL(hci_le_set_default_past_params(FD, 0, 0x01f4,
	    0x000A, 0));
	REJECT_EINVAL(hci_le_set_default_past_params(FD, 0, 0, 0x0009, 0));
	REJECT_EINVAL(hci_le_set_default_past_params(FD, 0, 0, 0x000A, 0x08));
	/* §7.8.80/.82/.84/.85 switching pattern length 2-75 antennae. */
	REJECT_EINVAL(hci_le_set_connless_cte_tx_params(FD, 0, 0x14, 0, 1, 76,
	    big));
	REJECT_EINVAL(hci_le_set_connless_iq_sampling_enable(FD, 1, 1, 1, 0, 76,
	    big));
	REJECT_EINVAL(hci_le_set_conn_cte_rx_params(FD, 1, 1, 1, 76, big));
	/* §7.8.80-.86 reserved values must not be placed on HCI. */
	REJECT_EINVAL(hci_le_set_connless_cte_tx_params(FD, 0xf0, 0x14, 0, 1,
	    2, big));
	REJECT_EINVAL(hci_le_set_connless_cte_tx_params(FD, 0, 1, 0, 1, 2,
	    big));
	REJECT_EINVAL(hci_le_set_connless_cte_tx_params(FD, 0, 2, 3, 1, 2,
	    big));
	REJECT_EINVAL(hci_le_set_connless_cte_tx_params(FD, 0, 2, 0, 0, 2,
	    big));
	REJECT_EINVAL(hci_le_set_connless_cte_tx_enable(FD, 0, 2));
	REJECT_EINVAL(hci_le_set_connless_iq_sampling_enable(FD, 0x0f00, 1, 1,
	    0, 2, big));
	REJECT_EINVAL(hci_le_set_connless_iq_sampling_enable(FD, 1, 1, 0, 0,
	    2, big));
	REJECT_EINVAL(hci_le_set_connless_iq_sampling_enable(FD, 1, 1, 1, 17,
	    2, big));
	REJECT_EINVAL(hci_le_set_conn_cte_rx_params(FD, 1, 1, 3, 2, big));
	REJECT_EINVAL(hci_le_set_conn_cte_tx_params(FD, 1, 0x80, 2, big));
	REJECT_EINVAL(hci_le_conn_cte_req_enable(FD, 1, 1, 0, 1, 0));
	REJECT_EINVAL(hci_le_conn_cte_req_enable(FD, 1, 1, 0, 2, 3));
	REJECT_EINVAL(hci_le_conn_cte_rsp_enable(FD, 1, 2));
	REJECT_EINVAL(hci_le_set_conn_cte_tx_params(FD, 1, 0x01, 76, big));
}

ATF_TC_WITHOUT_HEAD(validation_conn);
ATF_TC_BODY(validation_conn, tc)
{
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t huge[600];

	memset(huge, 0, sizeof(huge));

	/* §7.8.18 connection-update: exercise each operand of the guards. */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x0F00, 0x0006, 0x0006, 0,
	    0x000A));				/* handle > 0x0EFF */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x40, 0x0004, 0x0006, 0,
	    0x000A));				/* interval_min < 0x0006 */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x40, 0x0D00, 0x0D00, 0,
	    0x000A));				/* interval_min > 0x0C80 */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x40, 0x0006, 0x0004, 0,
	    0x000A));				/* interval_max < 0x0006 */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x40, 0x0040, 0x0020, 0,
	    0x000A));				/* min > max */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x40, 0x0006, 0x0006, 0x0200,
	    0x000A));				/* latency > 0x01F3 */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x40, 0x0006, 0x0006, 0,
	    0x0005));				/* timeout < 0x000A */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x40, 0x0006, 0x0006, 0,
	    0x0D00));				/* timeout > 0x0C80 */
	REJECT_EINVAL(hci_le_connection_update(FD, 0x40, 0x0C80, 0x0C80, 0,
	    0x000A));				/* timeout too short for interval */

	/* §7.8.33 data length tx_octets 0x001B-0x00FB, tx_time 0x0148-0x4290. */
	REJECT_EINVAL(hci_le_set_data_length(FD, 0x0F00, 0x001B, 0x0148));
	REJECT_EINVAL(hci_le_set_data_length(FD, 0x40, 0x0010, 0x0148));
	REJECT_EINVAL(hci_le_set_data_length(FD, 0x40, 0x0100, 0x0148));
	REJECT_EINVAL(hci_le_set_data_length(FD, 0x40, 0x001B, 0x0100));
	REJECT_EINVAL(hci_le_set_data_length(FD, 0x40, 0x001B, 0x5000));
	REJECT_EINVAL(hci_le_write_suggested_default_data_length(FD, 0x0010,
	    0x0148));
	REJECT_EINVAL(hci_le_write_suggested_default_data_length(FD, 0x001B,
	    0x5000));

	/* §7.8.47-49 handle range, PHY masks, and PHY_Options RFU value. */
	REJECT_EINVAL(hci_le_read_phy(FD, 0x0F00, NULL, NULL));
	REJECT_EINVAL(hci_le_set_default_phy(FD, 0x04, 0x01, 0x01));
	REJECT_EINVAL(hci_le_set_default_phy(FD, 0x00, 0x08, 0x01));
	REJECT_EINVAL(hci_le_set_default_phy(FD, 0x00, 0x01, 0x08));
	REJECT_EINVAL(hci_le_set_default_phy(FD, 0x00, 0x00, 0x01));
	REJECT_EINVAL(hci_le_set_default_phy(FD, 0x00, 0x01, 0x00));
	REJECT_EINVAL(hci_le_set_phy(FD, 0x0F00, 0x00, 0x01, 0x01, 0));
	REJECT_EINVAL(hci_le_set_phy(FD, 0x40, 0x04, 0x01, 0x01, 0));
	REJECT_EINVAL(hci_le_set_phy(FD, 0x40, 0x00, 0x08, 0x01, 0));
	REJECT_EINVAL(hci_le_set_phy(FD, 0x40, 0x00, 0x01, 0x08, 0));
	REJECT_EINVAL(hci_le_set_phy(FD, 0x40, 0x00, 0x00, 0x01, 0));
	REJECT_EINVAL(hci_le_set_phy(FD, 0x40, 0x00, 0x01, 0x00, 0));
	REJECT_EINVAL(hci_le_set_phy(FD, 0x40, 0x00, 0x01, 0x01, 0x0003));
	REJECT_EINVAL(hci_le_set_phy(FD, 0x40, 0x00, 0x01, 0x01, 0x0004));

	/* §7.8.123/.124 subrate ranges and algebraic invalid-parameter rules. */
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 0, 1, 0, 0, 0x000A));
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 1, 0x01F5, 0, 0, 0x000A));
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 4, 1, 0, 0, 0x000A));
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 1, 4, 0x01F4, 0, 0x000A));
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 1, 4, 0, 0x01F4, 0x000A));
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 1, 4, 0, 4, 0x000A));
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 1, 4, 0, 0, 0x0009));
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 1, 4, 0, 0, 0x0C81));
	REJECT_EINVAL(hci_le_set_default_subrate(FD, 1, 501, 0, 0, 0x000A));
	REJECT_EINVAL(hci_le_subrate_request(FD, 0x0F00, 1, 4, 0, 0,
	    0x000A));
	REJECT_EINVAL(hci_le_subrate_request(FD, 0x40, 4, 1, 0, 0, 0x000A));
	REJECT_EINVAL(hci_le_subrate_request(FD, 0x40, 1, 4, 0, 4, 0x000A));
	REJECT_EINVAL(hci_le_subrate_request(FD, 0x40, 1, 501, 0, 0,
	    0x000A));

	/* §7.8.117/.118 PHY 0x01-0x04. */
	REJECT_EINVAL(hci_le_enhanced_read_tx_power_level(FD, 0x0F00, 0x01,
	    NULL, NULL));
	REJECT_EINVAL(hci_le_enhanced_read_tx_power_level(FD, 0x40, 0x00,
	    NULL, NULL));
	REJECT_EINVAL(hci_le_enhanced_read_tx_power_level(FD, 0x40, 0x05,
	    NULL, NULL));
	REJECT_EINVAL(hci_le_read_remote_tx_power_level(FD, 0x0F00, 0x01));
	REJECT_EINVAL(hci_le_read_remote_tx_power_level(FD, 0x40, 0x00));
	REJECT_EINVAL(hci_le_read_remote_tx_power_level(FD, 0x40, 0x05));

	/* §7.8.119-121 Connection_Handle range 0x0000-0x0EFF. */
	REJECT_EINVAL(hci_le_set_path_loss_reporting_params(FD, 0x0F00, 0x40,
	    0x04, 0x10, 0x04, 0x000A));
	REJECT_EINVAL(hci_le_set_path_loss_reporting_enable(FD, 0x0F00, 0x01));
	REJECT_EINVAL(hci_le_set_tx_power_reporting_enable(FD, 0x0F00, 0x01,
	    0x01));
	/* §7.8.119 High_Threshold < Low_Threshold. */
	REJECT_EINVAL(hci_le_set_path_loss_reporting_params(FD, 0x40, 0x10, 0x04,
	    0x40, 0x04, 0x000A));
	/* §7.8.120 Enable RFU > 0x01. */
	REJECT_EINVAL(hci_le_set_path_loss_reporting_enable(FD, 0x40, 0x02));
	/* §7.8.121 Local/Remote enable RFU > 0x01 (each operand). */
	REJECT_EINVAL(hci_le_set_tx_power_reporting_enable(FD, 0x40, 0x02, 0x00));
	REJECT_EINVAL(hci_le_set_tx_power_reporting_enable(FD, 0x40, 0x00, 0x02));

	/* §7.8.66 extended create connection: encoded length must fit buffer. */
	REJECT_EINVAL(hci_le_ext_create_connection(FD, 0, 0, 0, addr, 0x01,
	    huge, sizeof(huge)));
	REJECT_EINVAL(hci_le_ext_create_connection(FD, 2, 0, 0, addr, 0x01,
	    huge, 16));
	REJECT_EINVAL(hci_le_ext_create_connection(FD, 0, 4, 0, addr, 0x01,
	    huge, 16));
	REJECT_EINVAL(hci_le_ext_create_connection(FD, 0, 0, 2, addr, 0x01,
	    huge, 16));
}

ATF_TC_WITHOUT_HEAD(validation_misc_privacy);
ATF_TC_BODY(validation_misc_privacy, tc)
{
	uint8_t huge[600];
	uint8_t out_cig = 0, out_cnt = 0;
	uint16_t handles[1] = { 0 };
	uint16_t cis_h[1] = { 0x0100 };
	uint16_t acl_h[1] = { 0x0001 };
	uint8_t bcode[16], bis[1] = { 1 };
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t irk[16];
	struct hci_scan_params scan;

	memset(huge, 0, sizeof(huge));
	memset(bcode, 0, sizeof(bcode));
	memset(irk, 0, sizeof(irk));
	hci_scan_params_default(&scan);

	/* §7.8.97 CIG: CIS_Count <= 0x1F, CIG_ID <= 0xEF, cmd must fit. */
	REJECT_EINVAL(hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0, 0, 0,
	    10, 10, 32, huge, 9, &out_cig, &out_cnt, handles));
	REJECT_EINVAL(hci_le_set_cig_params(FD, 0xF0, 10000, 10000, 0, 0, 0,
	    10, 10, 1, huge, 9, &out_cig, &out_cnt, handles));
	REJECT_EINVAL(hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0, 0, 0,
	    10, 10, 1, huge, sizeof(huge), &out_cig, &out_cnt, handles));
	/* §7.8.99 Create CIS: 1 <= CIS_Count <= 0x1F. */
	REJECT_EINVAL(hci_le_create_cis(FD, 0, cis_h, acl_h));
	REJECT_EINVAL(hci_le_create_cis(FD, 32, cis_h, acl_h));
	/* §7.8.103 Create BIG: 1 <= Num_BIS <= 0x1F, RTN <= 0x1E. */
	REJECT_EINVAL(hci_le_create_big(FD, 0, 0, 0, 10000, 100, 10, 0, 1, 0,
	    0, 0, bcode));
	REJECT_EINVAL(hci_le_create_big(FD, 0, 0, 32, 10000, 100, 10, 0, 1, 0,
	    0, 0, bcode));
	REJECT_EINVAL(hci_le_create_big(FD, 0, 0, 1, 10000, 100, 10, 0x1F, 1, 0,
	    0, 0, bcode));
	/* §7.8.106 BIG Create Sync: cmd must fit (huge Num_BIS). */
	REJECT_EINVAL(hci_le_big_create_sync(FD, 0, 0x0001, 0, bcode, 0, 0x0064,
	    0xFF, bis));
	/*
	 * hci_le_setup_iso_data_path() has no over-length arm to assert:
	 * cmd is sized 13+255 and codec_config_len is a uint8_t, so the
	 * maximum representable payload exactly fits the command buffer.
	 */
	/* §7.3.102 Set Min Encryption Key Size 7-16. */
	REJECT_EINVAL(hci_set_min_enc_key_size(FD, 6));
	REJECT_EINVAL(hci_set_min_enc_key_size(FD, 17));
	/* §7.8.45 RPA timeout 1-0x0E10. */
	REJECT_EINVAL(hci_le_set_rpa_timeout(FD, 0));
	REJECT_EINVAL(hci_le_set_rpa_timeout(FD, 0x0E11));
	/* §7.8.10/.11 scan params and enable RFU values reject before I/O. */
	REJECT_EINVAL(hci_le_set_scan_params(FD, NULL));
	scan.filter_dup = 2;
	REJECT_EINVAL(hci_le_set_scan_params(FD, &scan));
	hci_scan_params_default(&scan);
	REJECT_EINVAL(hci_le_set_scan_enable(FD, 2, 0));
	REJECT_EINVAL(hci_le_set_scan_enable(FD, 1, 2));
	REJECT_EINVAL(hci_le_set_ext_scan_params(FD, &scan, 0x02));
	REJECT_EINVAL(hci_le_set_ext_scan_params(FD, &scan, 0x08));
	/* §7.8.38-.40/.77 resolving-list and privacy-mode operand bounds. */
	REJECT_EINVAL(hci_le_add_dev_resolving_list(FD, 2, addr, irk, irk));
	REJECT_EINVAL(hci_le_add_dev_resolving_list(FD, 0, NULL, irk, irk));
	REJECT_EINVAL(hci_le_add_dev_resolving_list(FD, 0, addr, NULL, irk));
	REJECT_EINVAL(hci_le_add_dev_resolving_list(FD, 0, addr, irk, NULL));
	REJECT_EINVAL(hci_le_remove_dev_resolving_list(FD, 2, addr));
	REJECT_EINVAL(hci_le_remove_dev_resolving_list(FD, 0, NULL));
	REJECT_EINVAL(hci_le_set_addr_resolution_enable(FD, 2));
	REJECT_EINVAL(hci_le_set_privacy_mode(FD, 2, addr, 0));
	REJECT_EINVAL(hci_le_set_privacy_mode(FD, 0, NULL, 0));
	REJECT_EINVAL(hci_le_set_privacy_mode(FD, 0, addr, 2));
	/* §7.8.16/.17 filter accept list address type/address validation. */
	REJECT_EINVAL(hci_le_add_device_to_filter_accept_list(FD, 2, addr));
	REJECT_EINVAL(hci_le_add_device_to_filter_accept_list(FD, 0, NULL));
	REJECT_EINVAL(hci_le_remove_device_from_filter_accept_list(FD, 2, addr));
	REJECT_EINVAL(hci_le_remove_device_from_filter_accept_list(FD, 0, NULL));
}

/* ================================================================
 * hci_util.c — hci_disconnect (Core Spec Vol 4 Part E §7.1.6).
 * Command Status; status != 0 -> -1/EIO.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(disconnect_arms);
ATF_TC_BODY(disconnect_arms, tc)
{

	/* Verbose so the "failed, status=..." trace region executes too. */
	blued_verbose = 2;
	blued_daemonized = 0;

	mock_ok();
	ATF_CHECK_EQ(0, hci_disconnect(FD, 0x0040, 0x13));

	mock_status_bad();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_disconnect(FD, 0x0040, 0x13));
	ATF_CHECK_EQ(EIO, errno);

	blued_daemonized = 1;			/* syslog arm of the trace */
	mock_status_bad();
	ATF_CHECK_EQ(-1, hci_disconnect(FD, 0x0040, 0x13));

	mock_xport_fail(EIO);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_disconnect(FD, 0x0040, 0x13));

	/* Non-verbose failure so the LOG_HCI (verbose >= 1) False arm is taken. */
	blued_verbose = 0;
	mock_status_bad();
	ATF_CHECK_EQ(-1, hci_disconnect(FD, 0x0040, 0x13));

	blued_verbose = 0;
	blued_daemonized = 0;
}

/* ================================================================
 * hci_util.c — hci_send_raw_cmd.  Bypasses bt_devreq; sends on the raw
 * socket.  Success path drives send() on FD; we cannot mock send here,
 * so the parameter-copy branches are asserted on a real socketpair.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(send_raw_cmd_plen);
ATF_TC_BODY(send_raw_cmd_plen, tc)
{
	uint8_t p[4] = { 1, 2, 3, 4 };
	int sp[2];

	/*
	 * plen is a uint8_t, matching the HCI command packet length field.
	 * Drive the reachable arms on a real socketpair so the send() succeeds
	 * (return 0) and, on a closed peer, fails (return -1).
	 */
	signal(SIGPIPE, SIG_IGN);		/* peer-closed send must not abort */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sp));

	errno = 0;
	ATF_CHECK_EQ(-1, hci_send_raw_cmd(sp[0], 0x2005, NULL, 4));
	ATF_CHECK_EQ(EINVAL, errno);

	/* Success: send() writes to the connected peer -> 0. */
	ATF_CHECK_EQ(0, hci_send_raw_cmd(sp[0], 0x2005, p, 4));
	ATF_CHECK_EQ(0, hci_send_raw_cmd(sp[0], 0x2005, NULL, 0));

	/* Failure: close BOTH ends, then send() on the closed fd -> -1 (EBADF). */
	close(sp[1]);
	close(sp[0]);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_send_raw_cmd(sp[0], 0x2005, p, 4));
	ATF_CHECK(true);
}

/* ================================================================
 * hci_util.c — hci_get_con_handle (SIOC_HCI_RAW_NODE_GET_CON_LIST).
 * ================================================================ */
static void
con_reset(void)
{
	G_ioctl_fail = 0;
	G_con_count = 0;
	memset(G_cons, 0, sizeof(G_cons));
}

ATF_TC_WITHOUT_HEAD(get_con_handle_arms);
ATF_TC_BODY(get_con_handle_arms, tc)
{
	uint8_t addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
	uint8_t other[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	uint16_t handle = 0;

	blued_verbose = 2;			/* reach the success LOG_HCI trace */

	/* ioctl failure -> -1. */
	con_reset();
	G_ioctl_fail = 1;
	ATF_CHECK_EQ(-1, hci_get_con_handle(FD, addr, 0x00, &handle)); /* H-L3 */

	/* No connections -> not found -> ENOENT. */
	con_reset();
	G_con_count = 0;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_get_con_handle(FD, addr, 0x00, &handle)); /* H-L3 */
	ATF_CHECK_EQ(ENOENT, errno);

	/* First entry a non-LE link (skipped), second an LE-public match. */
	con_reset();
	G_con_count = 2;
	G_cons[0].link_type = NG_HCI_LINK_ACL;
	memcpy(&G_cons[0].bdaddr, addr, 6);
	G_cons[0].con_handle = 0x0011;
	G_cons[1].link_type = NG_HCI_LINK_LE_PUBLIC;
	memcpy(&G_cons[1].bdaddr, addr, 6);
	G_cons[1].con_handle = 0x0042;
	handle = 0;
	ATF_CHECK_EQ(0, hci_get_con_handle(FD, addr, 0x00, &handle)); /* H-L3: LE-public */
	ATF_CHECK_EQ(0x0042, handle);		/* con_handle extracted */

	/* LE-random link type also matches. */
	con_reset();
	G_con_count = 1;
	G_cons[0].link_type = NG_HCI_LINK_LE_RANDOM;
	memcpy(&G_cons[0].bdaddr, addr, 6);
	G_cons[0].con_handle = 0x0043;
	handle = 0;
	ATF_CHECK_EQ(0, hci_get_con_handle(FD, addr, 0x01, &handle)); /* H-L3: LE-random */
	ATF_CHECK_EQ(0x0043, handle);

	/* LE link but a different address -> not found. */
	con_reset();
	G_con_count = 1;
	G_cons[0].link_type = NG_HCI_LINK_LE_PUBLIC;
	memcpy(&G_cons[0].bdaddr, other, 6);
	G_cons[0].con_handle = 0x0044;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_get_con_handle(FD, addr, 0x00, &handle)); /* H-L3 */
	ATF_CHECK_EQ(ENOENT, errno);

	blued_verbose = 0;
}

/* ================================================================
 * hci_conn.c — l2cap_conn_param_update_req.  Adapter scan (bt_devopen +
 * hci_get_bdaddr) then con-handle lookup then hci_le_connection_update.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(conn_param_update_req);
ATF_TC_BODY(conn_param_update_req, tc)
{
	/*
	 * local[0] / rp[1] carry bit 1 (0x13 = 0b00010011) so that the shared
	 * mock payload doubles as both the matching local BD_ADDR (hci_get_bdaddr)
	 * and an LE Read Local Supported Features reply with the Connection
	 * Parameters Request bit set — the gate the HCI update path depends on
	 * (Core Spec Vol 6 Part B §4.6.2 / hci_conn.c l2cap_conn_param_update_req).
	 */
	uint8_t local[6] = { 0x13, 0x22, 0x33, 0x44, 0x55, 0x66 };
	uint8_t peer[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	uint8_t rp[7] = { 0x00, 0x13, 0x22, 0x33, 0x44, 0x55, 0x66 };

	blued_verbose = 2;			/* reach the success LOG_HCI trace */

	/* First adapter matches local addr; con handle found; update ok. */
	G_devopen_fd = 800;
	mock_ok_bytes(rp, sizeof(rp));		/* hci_get_bdaddr returns local */
	con_reset();
	G_con_count = 1;
	G_cons[0].link_type = NG_HCI_LINK_LE_PUBLIC;
	memcpy(&G_cons[0].bdaddr, peer, 6);
	G_cons[0].con_handle = 0x0040;
	ATF_CHECK_EQ(0, l2cap_conn_param_update_req(local, peer, 0,
	    0x0006, 0x0006, 0, 0x000A));
	blued_daemonized = 1;
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, l2cap_conn_param_update_req(local, peer, 0,
	    0x0006, 0x0006, 0, 0x000A));
	blued_daemonized = 0;
	blued_verbose = 0;

	/* con-handle lookup fails -> -1. */
	G_devopen_fd = 800;
	mock_ok_bytes(rp, sizeof(rp));
	con_reset();
	G_con_count = 0;
	ATF_CHECK_EQ(-1, l2cap_conn_param_update_req(local, peer, 0,
	    0x0006, 0x0006, 0, 0x000A));

	/* bt_devopen always fails -> fallback ubt0 also fails -> hci_fd<0. */
	G_devopen_fd = -1;
	ATF_CHECK_EQ(-1, l2cap_conn_param_update_req(local, peer, 0,
	    0x0006, 0x0006, 0, 0x000A));

	/*
	 * Adapter scan finds no match (all bdaddr reads reject), fallback ubt0
	 * opens, con-handle found, but every controller command is rejected --
	 * the LE Read Local Supported Features read fails, so the feature gate
	 * declines the HCI update (fallback path) and the call returns -1.
	 */
	G_devopen_fd = 800;
	mock_status_bad();			/* bdaddr + feature reads all fail */
	con_reset();
	G_con_count = 1;
	G_cons[0].link_type = NG_HCI_LINK_LE_PUBLIC;
	memcpy(&G_cons[0].bdaddr, peer, 6);
	G_cons[0].con_handle = 0x0040;
	ATF_CHECK_EQ(-1, l2cap_conn_param_update_req(local, peer, 0,
	    0x0006, 0x0006, 0, 0x000A));
}

/* ================================================================
 * hci_misc.c — hci_wait_encryption (Encryption Change event wait).
 * ================================================================ */
static int
enc_change_event(uint8_t *b, uint16_t handle, uint8_t status, uint8_t enable)
{
	b[0] = BT_CORE63_HCI_H4_EVENT_PACKET;	/* Part A §2, Table 2.1 */
	b[1] = BT_CORE63_HCI_EVENT_ENCRYPTION_CHANGE;	/* §7.7.8: 0x08 */
	b[2] = 4;				/* param length */
	b[3] = status;
	b[4] = handle & 0xFF;
	b[5] = (handle >> 8) & 0xFF;
	b[6] = enable;
	return (7);
}

static int
enc_change_v2_event(uint8_t *b, uint16_t handle, uint8_t status,
    uint8_t enable, uint8_t key_size)
{
	b[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	b[1] = BT_CORE63_HCI_ENCRYPTION_CHANGE_V2_EVENT;
	b[2] = 5;
	b[3] = status;
	b[4] = handle & 0xFF;
	b[5] = (handle >> 8) & 0xFF;
	b[6] = enable;
	b[7] = key_size;
	return (8);
}

ATF_TC_WITHOUT_HEAD(wait_encryption_arms);
ATF_TC_BODY(wait_encryption_arms, tc)
{
	uint8_t ev[16];
	int n;

	/* Success: matching handle, status 0, enable 1 -> 0. */
	recv_reset();
	n = enc_change_event(ev, 0x0040, 0x00, 0x01);
	recv_push_data(ev, n);
	ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));

	/*
	 * Core 6.3 Vol 4 Part E §7.7.8 gives Connection_Handle range
	 * 0x0000-0x0EFF.  Reserved upper bits must not be treated as ACL PB/BC
	 * flags; reject that event and accept the following exact handle.
	 */
	recv_reset();
	n = enc_change_event(ev, 0xF040, 0x00, 0x01);
	recv_push_data(ev, n);
	n = enc_change_event(ev, 0x0040, 0x00, 0x01);
	recv_push_data(ev, n);
	ATF_CHECK_EQ(0, hci_wait_encryption(FD,
	    BT_CORE63_HCI_ENCRYPTION_HANDLE_MIN + 0x0040, 5));

	/* Section 7.7.8 Encryption Change v2 (generated event code 0x59). */
	recv_reset();
	n = enc_change_v2_event(ev, 0x0040, 0x00, 0x01,
	    BT_CORE63_SMP_MAX_KEY_SIZE);
	recv_push_data(ev, n);
	ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));

	/* Reserved Encryption_Enabled must be rejected; exact LE 0x01 succeeds. */
	recv_reset();
	n = enc_change_event(ev, 0x0040, 0x00, 0x03);
	recv_push_data(ev, n);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_wait_encryption(FD, 0x0040, 5));
	ATF_CHECK_EQ(EACCES, errno);
	recv_reset();
	n = enc_change_event(ev, 0x0040, 0x00, 0x01);
	recv_push_data(ev, n);
	ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));

	/* Controller failure: status != 0 -> -1/EACCES. */
	recv_reset();
	n = enc_change_event(ev, 0x0040, 0x05, 0x01);
	recv_push_data(ev, n);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_wait_encryption(FD, 0x0040, 5));
	ATF_CHECK_EQ(EACCES, errno);

	/* Encryption not enabled: enable == 0 -> -1/EACCES. */
	recv_reset();
	n = enc_change_event(ev, 0x0040, 0x00, 0x00);
	recv_push_data(ev, n);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_wait_encryption(FD, 0x0040, 5));
	ATF_CHECK_EQ(EACCES, errno);

	/* Wrong handle first (continue), EAGAIN (continue), then match. */
	recv_reset();
	n = enc_change_event(ev, 0x0099, 0x00, 0x01);
	recv_push_data(ev, n);
	recv_push_err(EAGAIN);
	n = enc_change_event(ev, 0x0040, 0x00, 0x01);
	recv_push_data(ev, n);
	ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));

	/* Short packet (n < event header) then a matching event. */
	recv_reset();
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	recv_push_data(ev, 2);			/* < sizeof(evt) */
	n = enc_change_event(ev, 0x0040, 0x00, 0x01);
	recv_push_data(ev, n);
	ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));

	/* A non-encryption-change event (Command Status) -> event!=... False. */
	recv_reset();
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_COMMAND_STATUS;	/* passes the filter, ignored */
	ev[2] = 4;
	ev[3] = 0x00; ev[4] = 0x01; ev[5] = 0x05; ev[6] = 0x20;
	recv_push_data(ev, 7);
	n = enc_change_event(ev, 0x0040, 0x00, 0x01);
	recv_push_data(ev, n);
	ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));

	/* Encryption-change event too short for its ep, then a good one. */
	recv_reset();
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_ENCRYPTION_CHANGE;
	ev[2] = 1;
	recv_push_data(ev, 4);			/* n < evt + ep */
	n = enc_change_event(ev, 0x0040, 0x00, 0x01);
	recv_push_data(ev, n);
	ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));

	/* EINTR (continue arm) then a match, with a BTSnoop capture open so the
	 * in-loop hci_log_packet arm executes too. */
	{
		char path[] = "/tmp/hci_error_arms_enc.XXXXXX";
		int tfd = mkstemp(path);

		ATF_REQUIRE(tfd >= 0);
		close(tfd);
		hci_log_open(path);
		recv_reset();
		recv_push_err(EINTR);
		n = enc_change_event(ev, 0x0040, 0x00, 0x01);
		recv_push_data(ev, n);
		ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));
		hci_log_close();
		unlink(path);
	}

	/* recv error (non-EAGAIN) -> break -> timeout ETIMEDOUT. */
	recv_reset();
	recv_push_err(EIO);
	errno = 0;
	ATF_CHECK_EQ(-1, hci_wait_encryption(FD, 0x0040, 5));
	ATF_CHECK_EQ(ETIMEDOUT, errno);

	/* Zero timeout: deadline already reached -> immediate ETIMEDOUT. */
	recv_reset();
	errno = 0;
	ATF_CHECK_EQ(-1, hci_wait_encryption(FD, 0x0040, 0));
	ATF_CHECK_EQ(ETIMEDOUT, errno);

	/*
	 * Re-drive the success and controller-failure arms under verbose with
	 * blued_daemonized in {0,1} so the LOG_HCI "encryption change ..." trace
	 * regions (both fprintf and syslog) execute.
	 */
	blued_verbose = 2;
	for (int d = 0; d <= 1; d++) {
		blued_daemonized = d;
		recv_reset();
		n = enc_change_event(ev, 0x0040, 0x00, 0x01);
		recv_push_data(ev, n);
		ATF_CHECK_EQ(0, hci_wait_encryption(FD, 0x0040, 5));
		recv_reset();
		n = enc_change_event(ev, 0x0040, 0x05, 0x01);
		recv_push_data(ev, n);
		ATF_CHECK_EQ(-1, hci_wait_encryption(FD, 0x0040, 5));
	}
	blued_verbose = 0;
	blued_daemonized = 0;
}

/* ================================================================
 * hci_scan.c — legacy LE scan (hci_le_scan) with report parsing and
 * de-duplication merge.
 * ================================================================ */
/*
 * Build a legacy LE Advertising Report meta-event.  Layout after the
 * 3-byte event header: subevent(0x02) num_reports(1) then per report
 * event_type(1) addr_type(1) addr(6) data_len(1) data[] rssi(1).
 */
static int
legacy_adv_event(uint8_t *b, const uint8_t addr[6], uint8_t addr_type,
    const uint8_t *ad, uint8_t adlen, int8_t rssi)
{
	int i = 0;

	b[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
	b[i++] = BT_CORE63_HCI_EVENT_LE_META;
	b[i++] = 0;				/* length (unused by parser) */
	b[i++] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;		/* subevent 0x02 */
	b[i++] = 1;				/* num_reports */
	b[i++] = 0x00;				/* event_type ADV_IND */
	b[i++] = addr_type;
	memcpy(b + i, addr, 6);
	i += 6;
	b[i++] = adlen;
	memcpy(b + i, ad, adlen);
	i += adlen;
	b[i++] = (uint8_t)rssi;
	b[2] = (uint8_t)(i - 3);
	return (i);
}

ATF_TC_WITHOUT_HEAD(le_scan_report_merge);
ATF_TC_BODY(le_scan_report_merge, tc)
{
	struct ble_scan_result results[2];
	uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t b[6] = { 9, 9, 9, 9, 9, 9 };
	/* AD: Complete Local Name "Hi", Manufacturer 0x1234, UUID16 0x180F. */
	uint8_t ad_named[] = { 0x03, 0x09, 'H', 'i',
	    0x03, 0xFF, 0x34, 0x12,
	    0x03, 0x03, 0x0F, 0x18 };
	uint8_t ad_short[] = { 0x02, 0x08, 'H' };
	uint8_t ev[128];
	int n, nres = -1, rc;

	recv_reset();
	/* report A with a shortened name -> new entry (count 1). */
	n = legacy_adv_event(ev, a, 0, ad_short, sizeof(ad_short), -40);
	recv_push_data(ev, n);
	/* Complete name in the scan response must replace the shortened name. */
	n = legacy_adv_event(ev, a, 0, ad_named, sizeof(ad_named), -41);
	recv_push_data(ev, n);
	/* report B (random addr) -> new entry (count 2 == maxresults -> stop). */
	n = legacy_adv_event(ev, b, 0x01, ad_named, sizeof(ad_named), -50);
	recv_push_data(ev, n);

	mock_ok();				/* all setup commands succeed */
	rc = hci_le_scan(FD, 3, results, 2, &nres);
	ATF_CHECK_EQ(0, rc);
	ATF_CHECK_EQ(2, nres);
	/*
	 * The merge copied the name from the duplicate into entry A
	 * (Core Spec Vol 3 Part C §11 AD "Complete Local Name", type 0x09).
	 */
	ATF_CHECK_EQ(true, results[0].has_name);
	ATF_CHECK_EQ(true, results[0].name_complete);
	ATF_CHECK_STREQ("Hi", results[0].name);
	ATF_CHECK_EQ(0x1234, results[0].mfr_id);
	ATF_CHECK(results[0].num_svc_uuids >= 1);
	ATF_CHECK_EQ(0x180F, results[0].svc_uuids[0]);
}

ATF_TC_WITHOUT_HEAD(le_scan_setup_errors);
ATF_TC_BODY(le_scan_setup_errors, tc)
{
	struct ble_scan_result results[2];
	int nres = -1;

	blued_verbose = 2;			/* reach the 0x0C / pre-disable traces */

	/* Set Scan Parameters rejected (status 0x0C) -> -1/EIO. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 2;
	R.seq_status[0] = 0x0C;			/* pre-scan disable status!=0 */
	R.seq_status[1] = 0x0C;			/* set-params rejected */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_scan(FD, 1, results, 2, &nres));
	ATF_CHECK_EQ(EIO, errno);

	/* Set Scan Parameters transport failure on the 2nd call -> -1. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 2;
	R.seq_status[0] = 0x00;
	R.seq_fail[1] = 1;			/* params call: bt_devreq < 0 */
	ATF_CHECK_EQ(-1, hci_le_scan(FD, 1, results, 2, &nres));

	/* Set Scan Enable rejected (3rd call status!=0) -> -1/EIO. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 3;
	R.seq_status[0] = 0x00;
	R.seq_status[1] = 0x00;
	R.seq_status[2] = 0x0C;			/* enable rejected */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_scan(FD, 1, results, 2, &nres));
	ATF_CHECK_EQ(EIO, errno);

	/* Set Scan Enable transport failure on the 3rd call -> -1. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 3;
	R.seq_fail[2] = 1;
	ATF_CHECK_EQ(-1, hci_le_scan(FD, 1, results, 2, &nres));

	blued_verbose = 0;
}

ATF_TC_WITHOUT_HEAD(le_scan_malformed_reports);
ATF_TC_BODY(le_scan_malformed_reports, tc)
{
	struct ble_scan_result results[2];
	uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t ev[128];
	int n, nres = -1, i;
	char path[] = "/tmp/hci_error_arms_scan.XXXXXX";
	int tfd;

	/* Open a BTSnoop capture so the in-loop hci_log_packet arm executes. */
	tfd = mkstemp(path);
	ATF_REQUIRE(tfd >= 0);
	close(tfd);
	hci_log_open(path);

	/*
	 * A sequence exercising every receive-loop guard arm of hci_le_scan():
	 *   - bt_devrecv EAGAIN            -> continue
	 *   - short packet (n < evt hdr)   -> continue
	 *   - non-LE event                 -> continue
	 *   - LE meta, subevent != ADVREP  -> continue
	 *   - LE meta ADVREP, remain < 1   -> continue (no num_reports)
	 *   - report truncated < 8 header  -> break
	 *   - report truncated before len  -> break (remain<1 for data_len)
	 *   - report data_len > remaining   -> break (remain<data_len)
	 *   - a well-formed report          -> count reaches maxresults, stop
	 */
	recv_reset();
	recv_push_err(EAGAIN);			/* line: EAGAIN continue */

	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	recv_push_data(ev, 2);			/* short packet continue */

	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_COMMAND_STATUS;	/* not LE -> continue */
	ev[2] = 0;
	recv_push_data(ev, 3);

	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = 0x7F;				/* subevent != ADVREP -> continue */
	recv_push_data(ev, 4);

	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;		/* ADVREP but no num_reports byte */
	recv_push_data(ev, 4);

	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 3;
	ev[3] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	ev[4] = 1;				/* num_reports */
	ev[5] = 0x00;				/* only 1 byte -> remain<8 break */
	recv_push_data(ev, 6);

	/* report present but truncated right before data_len (remain<1 break). */
	i = 0;
	ev[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[i++] = BT_CORE63_HCI_EVENT_LE_META;
	ev[i++] = 0;
	ev[i++] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	ev[i++] = 1;
	ev[i++] = 0x00;				/* event_type */
	ev[i++] = 0x00;				/* addr_type */
	memcpy(ev + i, a, 6); i += 6;		/* addr, then nothing */
	ev[2] = (uint8_t)(i - 3);
	recv_push_data(ev, i);

	/* report claiming data_len 20 but only 2 data bytes (remain<data_len). */
	i = 0;
	ev[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[i++] = BT_CORE63_HCI_EVENT_LE_META;
	ev[i++] = 0;
	ev[i++] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	ev[i++] = 1;
	ev[i++] = 0x00;
	ev[i++] = 0x00;
	memcpy(ev + i, a, 6); i += 6;
	ev[i++] = 20;				/* data_len */
	ev[i++] = 0x02; ev[i++] = 0x01;		/* only 2 data bytes */
	ev[2] = (uint8_t)(i - 3);
	recv_push_data(ev, i);

	/* finally a valid report -> count == maxresults (1) -> loop stops. */
	n = legacy_adv_event(ev, a, 0, ad, sizeof(ad), -40);
	recv_push_data(ev, n);

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_scan(FD, 5, results, 1, &nres));
	ATF_CHECK_EQ(1, nres);

	hci_log_close();
	unlink(path);
}

/*
 * Corner branches of the legacy-scan receive loop and scan_result_merge:
 * the merge-skip arms (src lacks a field / dst already has it), the EINTR
 * continue, an empty-payload LE meta (remain<1), a report without a trailing
 * RSSI octet, a random-address report, and the immediate time-based loop exit
 * (duration 0).
 */
static int
legacy_adv_event_norssi(uint8_t *b, const uint8_t addr[6], uint8_t addr_type,
    const uint8_t *ad, uint8_t adlen)
{
	int i = 0;

	b[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
	b[i++] = BT_CORE63_HCI_EVENT_LE_META;
	b[i++] = 0;
	b[i++] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	b[i++] = 1;
	b[i++] = 0x00;
	b[i++] = addr_type;
	memcpy(b + i, addr, 6);
	i += 6;
	b[i++] = adlen;
	memcpy(b + i, ad, adlen);
	i += adlen;			/* no RSSI octet appended */
	b[2] = (uint8_t)(i - 3);
	return (i);
}

ATF_TC_WITHOUT_HEAD(le_scan_branch_corners);
ATF_TC_BODY(le_scan_branch_corners, tc)
{
	struct ble_scan_result results[4];
	uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t c[6] = { 3, 3, 3, 3, 3, 3 };
	uint8_t ad_named[] = { 0x03, 0x09, 'H', 'i', 0x03, 0xFF, 0x34, 0x12,
	    0x03, 0x03, 0x0F, 0x18 };
	uint8_t ad_flags[] = { 0x02, 0x01, 0x06 };
	uint8_t ev[128];
	int n, nres = -1;

	recv_reset();
	recv_push_err(EINTR);			/* EINTR continue arm */
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 0;				/* LE meta, remain==0 -> continue */
	recv_push_data(ev, 3);
	/* A with name+mfr+uuid -> new entry populated. */
	n = legacy_adv_event(ev, a, 0, ad_named, sizeof(ad_named), -40);
	recv_push_data(ev, n);
	/* A dup WITH a name while dst already named -> !dst->has_name False. */
	n = legacy_adv_event(ev, a, 0, ad_named, sizeof(ad_named), -41);
	recv_push_data(ev, n);
	/* A dup WITHOUT name/mfr -> src->has_name False, mfr cond False. */
	n = legacy_adv_event(ev, a, 0, ad_flags, sizeof(ad_flags), -42);
	recv_push_data(ev, n);
	/* Random-address report, no trailing RSSI octet -> remain>=1 False. */
	n = legacy_adv_event_norssi(ev, c, 0x01, ad_flags, sizeof(ad_flags));
	recv_push_data(ev, n);
	/* queue then drains -> recv error -> break. */

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_scan(FD, 5, results, 4, &nres));
	ATF_CHECK_EQ(1, nres);			/* C lacks mandatory RSSI */

	/* duration 0 -> while (time < end_time) false immediately (time-exit). */
	recv_reset();
	mock_ok();
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_scan(FD, 0, results, 4, &nres));
	ATF_CHECK_EQ(0, nres);

	/*
	 * One meta-event carrying two reports with maxresults == 1: the inner
	 * for-loop's (count < maxresults) condition goes false after the first
	 * report, exercising that branch.
	 */
	recv_reset();
	{
		uint8_t two[128];
		uint8_t b[6] = { 8, 8, 8, 8, 8, 8 };
		int i = 0, k;

		two[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
		two[i++] = BT_CORE63_HCI_EVENT_LE_META;
		two[i++] = 0;
		two[i++] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
		two[i++] = 2;			/* num_reports = 2 */
		for (k = 0; k < 2; k++) {
			two[i++] = 0x00;	/* event_type */
			two[i++] = 0x00;	/* addr_type */
			memcpy(two + i, k == 0 ? a : b, 6); i += 6;
			two[i++] = (uint8_t)sizeof(ad_flags);
			memcpy(two + i, ad_flags, sizeof(ad_flags));
			i += sizeof(ad_flags);
			two[i++] = (uint8_t)(-40);	/* rssi */
		}
		two[2] = (uint8_t)(i - 3);
		recv_push_data(two, i);
		mock_ok();
		nres = -1;
		ATF_CHECK_EQ(0, hci_le_scan(FD, 5, results, 1, &nres));
		ATF_CHECK_EQ(1, nres);
	}

	/*
	 * scan_result_merge's (dst->num_svc_uuids < 8) False arm: a device
	 * advertising eight 16-bit UUIDs fills the destination, and a duplicate
	 * carrying more finds the array already full.
	 */
	recv_reset();
	{
		uint8_t d[6] = { 2, 2, 2, 2, 2, 2 };
		uint8_t ad8[2 + 16];
		int j;

		ad8[0] = 0x11;			/* len: type + 8*2 UUID bytes */
		ad8[1] = 0x03;			/* Complete List of 16-bit UUIDs */
		for (j = 0; j < 16; j++)
			ad8[2 + j] = (uint8_t)j;
		n = legacy_adv_event(ev, d, 0, ad8, sizeof(ad8), -30);
		recv_push_data(ev, n);		/* fills 8 UUIDs */
		n = legacy_adv_event(ev, d, 0, ad8, sizeof(ad8), -31);
		recv_push_data(ev, n);		/* duplicate -> merge finds full */
		mock_ok();
		nres = -1;
		ATF_CHECK_EQ(0, hci_le_scan(FD, 5, results, 1, &nres));
	}

	/*
	 * Pre-scan disable returns a non-zero status while NON-verbose: the
	 * (blued_verbose >= 2) False arm of that trace guard (hci_scan.c:183).
	 */
	recv_reset();
	n = legacy_adv_event(ev, a, 0, ad_flags, sizeof(ad_flags), -40);
	recv_push_data(ev, n);
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 3;
	R.seq_status[0] = 0x0C;			/* pre-scan disable status != 0 */
	R.seq_status[1] = 0x00;			/* params ok */
	R.seq_status[2] = 0x00;			/* enable ok */
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_scan(FD, 5, results, 1, &nres));
}

/* ================================================================
 * hci_scan.c — extended LE scan (hci_le_ext_scan).
 * ================================================================ */
static int
ext_adv_event(uint8_t *b, const uint8_t addr[6], const uint8_t *ad,
    uint8_t adlen)
{
	int i = 0, j;

	b[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
	b[i++] = BT_CORE63_HCI_EVENT_LE_META;
	b[i++] = 0;
	b[i++] = BT_CORE63_HCI_LE_EXT_ADV_REPORT_SUBEVENT;	/* subevent 0x0D */
	b[i++] = 1;				/* num_reports */
	/* Extended report fixed header is 24 bytes (see hci_parse_ext_adv_report). */
	b[i++] = 0x00; b[i++] = 0x00;		/* event_type(2) */
	b[i++] = 0x00;				/* addr_type public */
	memcpy(b + i, addr, 6); i += 6;		/* addr */
	b[i++] = 0x01;				/* primary_phy */
	b[i++] = 0x01;				/* secondary_phy */
	b[i++] = 0x00;				/* advertising_sid */
	b[i++] = 0x00;				/* tx_power */
	b[i++] = (uint8_t)(-55);		/* rssi */
	b[i++] = 0x00; b[i++] = 0x00;		/* periodic_adv_interval(2) */
	b[i++] = 0x00;				/* direct_addr_type */
	for (j = 0; j < 6; j++)
		b[i++] = 0x00;			/* direct_addr(6) */
	b[i++] = adlen;				/* data_length */
	memcpy(b + i, ad, adlen); i += adlen;
	b[2] = (uint8_t)(i - 3);
	return (i);
}

ATF_TC_WITHOUT_HEAD(ext_scan_reports);
ATF_TC_BODY(ext_scan_reports, tc)
{
	struct ble_scan_result results[5];
	uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t b[6] = { 7, 7, 7, 7, 7, 7 };
	uint8_t ad_named[] = { 0x03, 0x09, 'H', 'i' };
	uint8_t ad_flags[] = { 0x02, 0x01, 0x06 };
	uint8_t leg[128], ext[128], ev[32];
	int n, nres = -1, i;
	char path[] = "/tmp/hci_error_arms_ext.XXXXXX";
	int tfd;

	blued_verbose = 2;			/* reach LOG_HCI(1/2) trace arms */
	tfd = mkstemp(path);
	ATF_REQUIRE(tfd >= 0);
	close(tfd);
	hci_log_open(path);			/* in-loop hci_log_packet arm */

	/*
	 * Exercise both report paths and every guard arm of hci_le_ext_scan's
	 * receive loop, terminating with a SCAN_TIMEOUT.  maxresults is large so
	 * the loop is driven by the scripted events, not the count bound.
	 */
	recv_reset();
	recv_push_err(EAGAIN);			/* EAGAIN -> continue */

	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	recv_push_data(ev, 2);			/* short packet -> continue */

	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_COMMAND_STATUS;	/* not LE -> continue */
	ev[2] = 0;
	recv_push_data(ev, 3);

	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 0;				/* LE meta, remain<1 -> continue */
	recv_push_data(ev, 3);

	/* Legacy path (subevent 0x02): num_reports missing -> continue. */
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	recv_push_data(ev, 4);

	/* Legacy new report addr A. */
	n = legacy_adv_event(leg, a, 0, ad_flags, sizeof(ad_flags), -40);
	recv_push_data(leg, n);
	/* Legacy duplicate addr A with a name -> scan_result_merge. */
	n = legacy_adv_event(leg, a, 0, ad_named, sizeof(ad_named), -41);
	recv_push_data(leg, n);

	/* Legacy truncated < 8-byte header -> break. */
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 3;
	ev[3] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	ev[4] = 1;
	ev[5] = 0x00;
	recv_push_data(ev, 6);

	/* Legacy truncated before data_len -> break. */
	i = 0;
	ev[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[i++] = BT_CORE63_HCI_EVENT_LE_META;
	ev[i++] = 0;
	ev[i++] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	ev[i++] = 1;
	ev[i++] = 0x00;
	ev[i++] = 0x00;
	memcpy(ev + i, a, 6); i += 6;
	ev[2] = (uint8_t)(i - 3);
	recv_push_data(ev, i);

	/* Legacy data_len > remaining -> break. */
	i = 0;
	ev[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[i++] = BT_CORE63_HCI_EVENT_LE_META;
	ev[i++] = 0;
	ev[i++] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	ev[i++] = 1;
	ev[i++] = 0x00;
	ev[i++] = 0x00;
	memcpy(ev + i, a, 6); i += 6;
	ev[i++] = 20;
	ev[i++] = 0x02; ev[i++] = 0x01;
	ev[2] = (uint8_t)(i - 3);
	recv_push_data(ev, i);

	/* Extended path (subevent 0x0D): num_reports missing -> continue. */
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = BT_CORE63_HCI_LE_EXT_ADV_REPORT_SUBEVENT;
	recv_push_data(ev, 4);

	/* Extended report truncated below the 24-byte header -> consumed 0. */
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 4;
	ev[3] = BT_CORE63_HCI_LE_EXT_ADV_REPORT_SUBEVENT;
	ev[4] = 1;
	ev[5] = 0x00; ev[6] = 0x00;
	recv_push_data(ev, 7);

	/* Extended new report addr B, random addr_type (0x01) -> RANDOM arm. */
	n = ext_adv_event(ext, b, ad_flags, sizeof(ad_flags));
	ext[7] = 0x01;				/* addr_type = random */
	recv_push_data(ext, n);
	/* Extended duplicate addr B with a name -> scan_result_merge. */
	n = ext_adv_event(ext, b, ad_named, sizeof(ad_named));
	recv_push_data(ext, n);

	/* SCAN_TIMEOUT -> break out of the loop. */
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = BT_CORE63_HCI_LE_SCAN_TIMEOUT_SUBEVENT;
	recv_push_data(ev, 4);

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 2, results, 5, &nres, 0x05));
	ATF_CHECK(nres >= 2);
	ATF_CHECK_EQ(true, results[0].has_name);	/* legacy merge landed */

	hci_log_close();
	unlink(path);
	blued_verbose = 0;
}

/*
 * duration > 655 selects the "scan until disabled" duration=0 encoding, and
 * a transport failure on the final Set Ext Scan Disable drives the warn() arm.
 */
ATF_TC_WITHOUT_HEAD(ext_scan_long_duration_and_final_disable_fail);
ATF_TC_BODY(ext_scan_long_duration_and_final_disable_fail, tc)
{
	struct ble_scan_result results[2];
	uint8_t ev[16];
	int nres = -1;

	blued_verbose = 2;
	recv_reset();
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = BT_CORE63_HCI_LE_SCAN_TIMEOUT_SUBEVENT;	/* end loop immediately */
	recv_push_data(ev, 4);

	/* params ok, enable ok, final disable transport-fails (warn arm). */
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 3;
	R.seq_status[0] = 0x00;
	R.seq_status[1] = 0x00;
	R.seq_fail[2] = 1;			/* final disable bt_devreq < 0 */
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1000, results, 2, &nres, 0x01));

	/* Same, but final disable returns status != 0 (LOG arm). */
	recv_reset();
	recv_push_data(ev, 4);
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 3;
	R.seq_status[0] = 0x00;
	R.seq_status[1] = 0x00;
	R.seq_status[2] = 0x0C;			/* final disable status != 0 */
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 700, results, 2, &nres, 0x01));

	blued_verbose = 0;
}

ATF_TC_WITHOUT_HEAD(ext_scan_timeout_and_ignored);
ATF_TC_BODY(ext_scan_timeout_and_ignored, tc)
{
	struct ble_scan_result results[2];
	uint8_t ev[16];
	int nres = -1;

	/* An ignored LE subevent (verbose trace) then a SCAN_TIMEOUT -> break. */
	blued_verbose = 2;
	recv_reset();
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = 0x7F;				/* unknown subevent -> ignored */
	recv_push_data(ev, 4);
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = BT_CORE63_HCI_LE_SCAN_TIMEOUT_SUBEVENT;	/* subevent 0x11 -> break */
	recv_push_data(ev, 4);

	mock_ok();
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));
	blued_verbose = 0;
}

ATF_TC_WITHOUT_HEAD(ext_scan_setup_errors);
ATF_TC_BODY(ext_scan_setup_errors, tc)
{
	struct ble_scan_result results[2];
	int nres = -1;

	blued_verbose = 2;			/* reach the 0x0C retry LOG_HCI arms */

	/* Set Ext Scan Params transport failure on the 1st call -> -1. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 1;
	R.seq_fail[0] = 1;
	ATF_CHECK_EQ(-1, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));

	/*
	 * Set Ext Scan Params rejected with 0x0C -> the encoder disables and
	 * retries; make the retry (3rd command) succeed so the scan proceeds
	 * to the receive loop, which we terminate with a scan-timeout event.
	 * Sequence: [0]=params 0x0C, [1]=disable ok, [2]=params retry ok,
	 * [3]=enable ok, [4]=final disable ok.
	 */
	recv_reset();
	{
		uint8_t ev[16];

		ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
		ev[1] = BT_CORE63_HCI_EVENT_LE_META;
		ev[2] = 1;
		ev[3] = BT_CORE63_HCI_LE_SCAN_TIMEOUT_SUBEVENT;
		recv_push_data(ev, 4);
	}
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 8;
	R.seq_status[0] = 0x0C;			/* params rejected */
	R.seq_status[1] = 0x00;			/* disable */
	R.seq_status[2] = 0x00;			/* params retry ok */
	R.seq_status[3] = 0x00;			/* enable ok */
	/* remaining default 0 (final disable ok) */
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));

	/* Set Ext Scan Params rejected 0x0C and the retry also fails -> -1. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 3;
	R.seq_status[0] = 0x0C;			/* params rejected */
	R.seq_status[1] = 0x00;			/* disable */
	R.seq_status[2] = 0x0C;			/* retry still rejected */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));
	ATF_CHECK_EQ(EIO, errno);

	/* Non-0x0C rejection on params -> immediate -1/EIO (no retry). */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 1;
	R.seq_status[0] = 0x11;			/* some other status */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));
	ATF_CHECK_EQ(EIO, errno);

	/* Set Ext Scan Enable rejected -> -1/EIO. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 2;
	R.seq_status[0] = 0x00;			/* params ok */
	R.seq_status[1] = 0x0C;			/* enable rejected */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));
	ATF_CHECK_EQ(EIO, errno);

	/* Set Ext Scan Enable transport failure -> -1. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 2;
	R.seq_status[0] = 0x00;
	R.seq_fail[1] = 1;
	ATF_CHECK_EQ(-1, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));

	blued_verbose = 0;
}

/*
 * Re-drive the scan success and rejection paths with blued_daemonized in
 * {0,1} so the syslog side of every LOG_HCI/LOG_L2C trace region in
 * hci_le_scan / hci_le_ext_scan executes (the fprintf side is hit by the
 * dedicated cases above).
 */
ATF_TC_WITHOUT_HEAD(scan_daemonized_log_sweep);
ATF_TC_BODY(scan_daemonized_log_sweep, tc)
{
	struct ble_scan_result results[2];
	uint8_t a[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t tev[16];
	uint8_t ev[64];
	int n, nres, d;

	tev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	tev[1] = BT_CORE63_HCI_EVENT_LE_META;
	tev[2] = 1;
	tev[3] = BT_CORE63_HCI_LE_SCAN_TIMEOUT_SUBEVENT;

	/*
	 * Three passes: verbose+fprintf (d=0), verbose+syslog (d=1), and
	 * non-verbose (d=2) so each LOG site's (verbose >= lvl) False arm is
	 * also taken.
	 */
	for (d = 0; d <= 2; d++) {
		blued_verbose = (d == 2) ? 0 : 2;
		blued_daemonized = (d == 1) ? 1 : 0;

		/* legacy scan happy path (one report fills maxresults=1). */
		recv_reset();
		n = legacy_adv_event(ev, a, 0, ad, sizeof(ad), -40);
		recv_push_data(ev, n);
		mock_ok();
		nres = -1;
		(void)hci_le_scan(FD, 5, results, 1, &nres);

		/* legacy scan: params rejected 0x0C (0x0C trace). */
		recv_reset();
		memset(&R, 0, sizeof(R));
		R.use_seq = 1;
		R.seq_len = 2;
		R.seq_status[0] = 0x0C;
		R.seq_status[1] = 0x0C;
		(void)hci_le_scan(FD, 1, results, 2, &nres);

		/* extended scan happy path, terminated by SCAN_TIMEOUT. */
		recv_reset();
		recv_push_data(tev, 4);
		mock_ok();
		(void)hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01);

		/* extended scan: params rejected, non-0x0C -> EIO trace. */
		recv_reset();
		memset(&R, 0, sizeof(R));
		R.use_seq = 1;
		R.seq_len = 1;
		R.seq_status[0] = 0x11;
		(void)hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01);

		/* extended scan: enable rejected -> EIO trace. */
		recv_reset();
		memset(&R, 0, sizeof(R));
		R.use_seq = 1;
		R.seq_len = 2;
		R.seq_status[0] = 0x00;
		R.seq_status[1] = 0x0C;
		(void)hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01);
	}

	blued_verbose = 0;
	blued_daemonized = 0;
	ATF_CHECK(true);
}

/* ================================================================
 * hci_conn.c — LE CoC / ECBFC connect encoders (socket-layer seam).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(coc_connect_arms);
ATF_TC_BODY(coc_connect_arms, tc)
{
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	int fd, d;

	blued_verbose = 2;			/* reach LOG_L2C traces */

	/* Loop the fprintf (daemonized 0) and syslog (daemonized 1) arms. */
	for (d = 0; d <= 1; d++) {
		blued_daemonized = d;

		/* Success, mtu > 0 (SO_L2CAP_IMTU set). */
		sock_reset();
		fd = ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080, 512);
		ATF_CHECK(fd >= FAKEFD_BASE);

		/* Success, mtu == 0 (skip the IMTU setsockopt branch). */
		sock_reset();
		fd = ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080, 0);
		ATF_CHECK(fd >= FAKEFD_BASE);

		/* socket() failure -> -1. */
		sock_reset();
		G_sock_fail = 1;
		ATF_CHECK_EQ(-1, ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080,
		    512));

		/* bind() failure -> -1. */
		sock_reset();
		G_bind_fail = 1;
		ATF_CHECK_EQ(-1, ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080,
		    512));

		/* connect() failure -> -1. */
		sock_reset();
		G_connect_fail = 1;
		ATF_CHECK_EQ(-1, ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080,
		    512));
	}

	/* A non-verbose pass so each LOG_L2C site's (verbose >= 1) False arm
	 * is also taken. */
	blued_verbose = 0;
	sock_reset();
	fd = ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080, 512);
	ATF_CHECK(fd >= FAKEFD_BASE);
	sock_reset();
	G_sock_fail = 1;
	ATF_CHECK_EQ(-1, ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080, 512));
	sock_reset();
	G_bind_fail = 1;
	ATF_CHECK_EQ(-1, ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080, 512));
	sock_reset();
	G_connect_fail = 1;
	ATF_CHECK_EQ(-1, ble_coc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x0080, 512));

	blued_verbose = 0;
	blued_daemonized = 0;
}

ATF_TC_WITHOUT_HEAD(ecbfc_connect_arms);
ATF_TC_BODY(ecbfc_connect_arms, tc)
{
	uint8_t addr[6] = { 1, 2, 3, 4, 5, 6 };
	int fds[5];
	int d;

	blued_verbose = 2;			/* reach LOG_L2C traces */

	for (d = 0; d <= 1; d++) {
		blued_daemonized = d;

		/* Pre-I/O parameter validation (Core Spec Vol 3 Part A §4.25). */
		sock_reset();
		errno = 0;
		ATF_CHECK_EQ(-1, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    0, 0, fds));			/* count < 1 */
		ATF_CHECK_EQ(EINVAL, errno);
		errno = 0;
		ATF_CHECK_EQ(-1, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    0, 6, fds));			/* count > 5 */
		ATF_CHECK_EQ(EINVAL, errno);
		errno = 0;
		ATF_CHECK_EQ(-1, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    0, 2, NULL));			/* fds == NULL */
		ATF_CHECK_EQ(EINVAL, errno);

		/* Success opening 3 channels, mtu==0 -> default 512 branch. */
		sock_reset();
		ATF_CHECK_EQ(3, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    0, 3, fds));

		/* Success with explicit mtu. */
		sock_reset();
		ATF_CHECK_EQ(2, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    256, 2, fds));

		/* socket() failure on first channel -> 0 opened (break). */
		sock_reset();
		G_sock_fail = 1;
		ATF_CHECK_EQ(0, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    512, 3, fds));

		/* SO_L2CAP_ECBFC setsockopt failure -> 0 opened (break). */
		sock_reset();
		G_ecbfc_opt_fail = 1;
		ATF_CHECK_EQ(0, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    512, 3, fds));

		/* bind() failure -> 0 opened (break). */
		sock_reset();
		G_bind_fail = 1;
		ATF_CHECK_EQ(0, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    512, 3, fds));

		/* connect() failure -> 0 opened (break). */
		sock_reset();
		G_connect_fail = 1;
		ATF_CHECK_EQ(0, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80,
		    512, 3, fds));
	}

	/* Non-verbose pass for the (verbose >= 1) False arm of each LOG_L2C. */
	blued_verbose = 0;
	sock_reset();
	ATF_CHECK_EQ(3, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80, 0, 3,
	    fds));
	sock_reset();
	G_sock_fail = 1;
	ATF_CHECK_EQ(0, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80, 512, 3,
	    fds));
	sock_reset();
	G_ecbfc_opt_fail = 1;
	ATF_CHECK_EQ(0, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80, 512, 3,
	    fds));
	sock_reset();
	G_bind_fail = 1;
	ATF_CHECK_EQ(0, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80, 512, 3,
	    fds));
	sock_reset();
	G_connect_fail = 1;
	ATF_CHECK_EQ(0, ble_ecbfc_connect(NULL, addr, BDADDR_LE_PUBLIC, 0x80, 512, 3,
	    fds));

	blued_verbose = 0;
	blued_daemonized = 0;
}

ATF_TC_WITHOUT_HEAD(ecbfc_reconfig_arms);
ATF_TC_BODY(ecbfc_reconfig_arms, tc)
{
	int d;

	blued_verbose = 2;			/* reach LOG_L2C traces */

	for (d = 0; d <= 1; d++) {
		blued_daemonized = d;

		/* setsockopt(SO_L2CAP_RECONFIG) success -> 0. */
		sock_reset();
		ATF_CHECK_EQ(0, ble_ecbfc_reconfig(FAKEFD_BASE, 512, 256));

		/* setsockopt failure -> -1. */
		sock_reset();
		G_reconfig_fail = 1;
		ATF_CHECK_EQ(-1, ble_ecbfc_reconfig(FAKEFD_BASE, 512, 256));
	}

	/* Non-verbose pass for the (verbose >= 1) False arms. */
	blued_verbose = 0;
	sock_reset();
	ATF_CHECK_EQ(0, ble_ecbfc_reconfig(FAKEFD_BASE, 512, 256));
	sock_reset();
	G_reconfig_fail = 1;
	ATF_CHECK_EQ(-1, ble_ecbfc_reconfig(FAKEFD_BASE, 512, 256));

	blued_verbose = 0;
	blued_daemonized = 0;
}

ATF_TC_WITHOUT_HEAD(iso_connect_socket_arms);
ATF_TC_BODY(iso_connect_socket_arms, tc)
{
	uint8_t src[6] = { 1, 2, 3, 4, 5, 6 };
	uint8_t peer[6] = { 6, 5, 4, 3, 2, 1 };
	int fd;

	sock_reset();
	G_sock_fail = 1;
	ATF_CHECK_EQ(-1, ble_iso_connect(src, peer, BDADDR_LE_RANDOM,
	    0x40, 120));

	sock_reset();
	G_bind_fail = 1;
	ATF_CHECK_EQ(-1, ble_iso_connect(src, peer, BDADDR_LE_RANDOM,
	    0x40, 120));

	sock_reset();
	G_connect_fail = 1;
	ATF_CHECK_EQ(-1, ble_iso_connect(src, peer, BDADDR_LE_RANDOM,
	    0x40, 120));

	sock_reset();
	fd = ble_iso_connect(NULL, NULL, BDADDR_LE_PUBLIC, 0x41, 0);
	ATF_CHECK(fd >= FAKEFD_BASE);
	if (fd >= 0)
		close(fd);
}

/* ================================================================
 * hci_util.c — hci_devreq_logged_locked BTSnoop logging branches.
 * With a capture file open, hci_log_enabled() is true, so the command
 * and event logging arms (Command Complete and Command Status) execute.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(devreq_logging_paths);
ATF_TC_BODY(devreq_logging_paths, tc)
{
	char path[] = "/tmp/hci_error_arms_snoop.XXXXXX";
	int tfd;

	tfd = mkstemp(path);
	ATF_REQUIRE(tfd >= 0);
	close(tfd);

	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	/* Command Complete path (hci_reset uses COMMAND_COMPL). */
	mock_ok();
	ATF_CHECK_EQ(0, hci_reset(FD));

	/* A command with return parameters (Read Local Features) -> rlen>0. */
	mock_ok();
	(void)hci_le_read_local_features(FD, &(uint64_t){ 0 });

	/* Command Status path (hci_disconnect uses COMMAND_STATUS). */
	mock_ok();
	ATF_CHECK_EQ(0, hci_disconnect(FD, 0x0040, 0x13));

	/*
	 * Transport failure with logging enabled: bt_devreq returns < 0 so the
	 * response-logging guard's (ret == 0) operand takes its False arm.
	 */
	mock_xport_fail(EIO);
	(void)hci_reset(FD);

	/*
	 * A command whose parameter length exceeds 255 exercises the
	 * (plen > 255) clamp in hci_devreq_logged_locked's command-logging
	 * path.  LE Set CIG Parameters with 31 CIS entries builds a
	 * 15 + 31*9 = 294-byte command parameter.
	 */
	{
		uint8_t cis_params[31 * 9];
		uint8_t out_cig = 0, out_cnt = 0;
		uint16_t handles[31];
		uint8_t rp[3] = { 0x00, 0x05, 0x00 };

		memset(cis_params, 0, sizeof(cis_params));
		memset(handles, 0, sizeof(handles));
		mock_ok_bytes(rp, sizeof(rp));
		(void)hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0, 0, 0,
		    10, 10, 31, cis_params, sizeof(cis_params), &out_cig,
		    &out_cnt, handles);
	}

	hci_log_close();
	unlink(path);
	ATF_CHECK(true);
}

/* ================================================================
 * hci_log.c — logger error/edge branches.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(hci_log_edges);
ATF_TC_BODY(hci_log_edges, tc)
{
	char path[] = "/tmp/hci_error_arms_log.XXXXXX";
	uint8_t data[8] = { 0x01, 0x02, 0x03, 0x04 };
	int tfd;

	/* close when not open -> the (log_fd >= 0) false arm. */
	hci_log_close();
	ATF_CHECK_EQ(false, hci_log_enabled());

	/* open on an unwritable path -> open() fails -> stays disabled. */
	hci_log_open("/nonexistent-dir-xyz/hci.log");
	ATF_CHECK_EQ(false, hci_log_enabled());

	/* A recoverable short header write is completed by the write-all loop. */
	tfd = mkstemp(path);
	ATF_REQUIRE(tfd >= 0);
	close(tfd);
	G_write_fault = 1;			/* one-shot short write of hdr */
	hci_log_open(path);
	ATF_CHECK_EQ(true, hci_log_enabled());

	/* Reopen cleanly and exercise hci_log_l2cap plus the writev arms. */
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());
	hci_log_l2cap(0x0040, 0x0004, data, 4, false);	/* normal ACL log */
	/* Oversized L2CAP PDU: len > UINT16_MAX truncate then early return. */
	hci_log_l2cap(0x0040, 0x0004, data, 70000, false);

	/* writev short-write on a packet log -> logger self-closes. */
	G_writev_fault = 2;
	hci_log_packet(HCI_LOG_CMD, data, 4, false);
	ATF_CHECK_EQ(false, hci_log_enabled());

	/* writev hard-failure (-1) on a packet log -> self-close (ret<0 arm). */
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());
	G_writev_fault = 1;
	hci_log_packet(HCI_LOG_EVT, data, 4, true);
	ATF_CHECK_EQ(false, hci_log_enabled());

	/* writev hard-failure (-1) on an L2CAP log -> self-close (ret<0 arm). */
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());
	G_writev_fault = 1;
	hci_log_l2cap(0x0040, 0x0006, data, 4, true);
	ATF_CHECK_EQ(false, hci_log_enabled());

	/* writev short-write on an L2CAP log -> self-close (ret<expected arm). */
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());
	G_writev_fault = 2;
	hci_log_l2cap(0x0040, 0x0004, data, 4, false);
	ATF_CHECK_EQ(false, hci_log_enabled());

	hci_log_close();
	unlink(path);
}

/* ================================================================
 * hci_util.c — hci_devreq_logged response-logging compound guard.
 * Direct calls with a BTSnoop capture open drive the operand False arms
 * of "ret==0 && enabled && rlen>0 && rparam!=NULL" plus the Command
 * Status branch and the log_rlen>252 clamp.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(devreq_logged_response_variants);
ATF_TC_BODY(devreq_logged_response_variants, tc)
{
	char path[] = "/tmp/hci_error_arms_dl.XXXXXX";
	uint8_t big[300];
	struct bt_devreq r;
	int tfd;

	tfd = mkstemp(path);
	ATF_REQUIRE(tfd >= 0);
	close(tfd);
	hci_log_open(path);
	ATF_REQUIRE(hci_log_enabled());

	/* rlen == 0 -> (r->rlen > 0) False operand. */
	memset(&r, 0, sizeof(r));
	r.opcode = 0x0C03;
	r.rparam = big;
	r.rlen = 0;
	r.event = BT_CORE63_HCI_EVENT_COMMAND_COMPLETE;
	mock_ok();
	ATF_CHECK_EQ(0, hci_devreq_logged(FD, &r, 1));

	/* rparam == NULL -> (r->rparam != NULL) False operand. */
	memset(&r, 0, sizeof(r));
	r.opcode = 0x0C03;
	r.rparam = NULL;
	r.rlen = 8;
	r.event = BT_CORE63_HCI_EVENT_COMMAND_COMPLETE;
	mock_ok();
	ATF_CHECK_EQ(0, hci_devreq_logged(FD, &r, 1));

	/* rlen > 252 -> the Command Complete log_rlen clamp. */
	memset(&r, 0, sizeof(r));
	memset(big, 0, sizeof(big));
	r.opcode = 0x0C03;
	r.rparam = big;
	r.rlen = 260;
	r.event = BT_CORE63_HCI_EVENT_COMMAND_COMPLETE;
	mock_ok_bytes(big, 1);
	ATF_CHECK_EQ(0, hci_devreq_logged(FD, &r, 1));

	/* event = Command Status -> the non-Command-Complete log branch. */
	memset(&r, 0, sizeof(r));
	r.opcode = 0x0C03;
	r.rparam = big;
	r.rlen = 4;
	r.event = BT_CORE63_HCI_EVENT_COMMAND_STATUS;
	mock_ok();
	ATF_CHECK_EQ(0, hci_devreq_logged(FD, &r, 1));

	hci_log_close();
	unlink(path);
}

/*
 * enable-style encoders whose success trace uses a
 * (enable ? "enabled" : "disabled") ternary: drive enable == 0 (the
 * verbose sweep drives enable == 1) under verbose so the ternary's other
 * arm executes.
 */
ATF_TC_WITHOUT_HEAD(enable_ternary_disabled_arm);
ATF_TC_BODY(enable_ternary_disabled_arm, tc)
{
	int d;

	blued_verbose = 2;
	for (d = 0; d <= 1; d++) {
		blued_daemonized = d;
		mock_ok();
		(void)hci_le_set_addr_resolution_enable(FD, 0);
		mock_ok();
		(void)hci_le_set_path_loss_reporting_enable(FD, 0x40, 0);
		mock_ok();
		(void)hci_le_set_ext_adv_enable(FD, 0, 0);
		mock_ok();
		(void)hci_le_set_periodic_adv_enable(FD, 0, 0);
		mock_ok();
		(void)hci_le_set_periodic_adv_receive_enable(FD, 0x0001, 0);
		mock_ok();
		(void)hci_le_set_connless_cte_tx_enable(FD, 0, 0);
		mock_ok();
		(void)hci_le_conn_cte_req_enable(FD, 0x0001, 0, 0x000A, 0x14, 0);
		mock_ok();
		(void)hci_le_conn_cte_rsp_enable(FD, 0x0001, 0);
	}
	blued_verbose = 0;
	blued_daemonized = 0;
	ATF_CHECK(true);
}

/* ================================================================
 * Read-command NULL out-parameter guards (the "!= NULL" False arms),
 * plus the CTE/BIS "length > 0" False arms and node/host-support edges.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(read_cmd_null_outparams);
ATF_TC_BODY(read_cmd_null_outparams, tc)
{
	uint8_t rp[32];

	/* Each read command must succeed while extracting into NULL (skip). */
	memset(rp, 0, sizeof(rp));
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_phy(FD, 0x0040, NULL, NULL));
	/*
	 * The advertising-capability readers require non-NULL outputs and have
	 * dedicated EINVAL coverage in hci_devreq_mock_test.  This case keeps
	 * the sibling read encoders' NULL-skip arms grouped here.
	 */
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_periodic_adv_list_size(FD, NULL));
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_antenna_info(FD, NULL, NULL, NULL, NULL));
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_buffer_size_v2(FD, NULL, NULL, NULL, NULL));
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_tx_sync(FD, 0x0040, NULL, NULL, NULL));
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_iso_link_quality(FD, 0x0040, NULL, NULL,
	    NULL, NULL, NULL, NULL, NULL));
	mock_ok_bytes(rp, sizeof(rp));
	ATF_CHECK_EQ(0, hci_le_read_auth_payload_timeout(FD, 0x0040, NULL));

	/* Set CIG Params with NULL out_cis_handles (the handles-skip arm). */
	{
		uint8_t cis_params[9];
		uint8_t rpc[5] = { 0x00, 0x05, 0x01, 0x60, 0x00 };
		uint8_t oc = 0, on = 0;

		memset(cis_params, 0, sizeof(cis_params));
		mock_ok_bytes(rpc, sizeof(rpc));
		ATF_CHECK_EQ(0, hci_le_set_cig_params(FD, 0x05, 10000, 10000, 0,
		    0, 0, 10, 10, 1, cis_params, sizeof(cis_params), &oc, &on,
		    NULL));
	}
}

ATF_TC_WITHOUT_HEAD(cte_pattern_validation_and_iso_edges);
ATF_TC_BODY(cte_pattern_validation_and_iso_edges, tc)
{
	uint8_t bcode[16];

	memset(bcode, 0, sizeof(bcode));

	/* Enabled CTE commands require the spec's 2-75-entry antenna array. */
	REJECT_EINVAL(hci_le_set_connless_cte_tx_params(FD, 0, 0x14, 0, 1, 0,
	    NULL));
	REJECT_EINVAL(hci_le_set_connless_iq_sampling_enable(FD, 1, 1, 1, 0,
	    2, NULL));
	REJECT_EINVAL(hci_le_set_conn_cte_rx_params(FD, 1, 1, 1, 2, NULL));
	REJECT_EINVAL(hci_le_set_conn_cte_tx_params(FD, 1, 0x01, 2, NULL));

	/* On disable, the receive parameters are explicitly ignored. */
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_connless_iq_sampling_enable(FD, 1, 0, 0, 0,
	    0, NULL));
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_set_conn_cte_rx_params(FD, 1, 0, 0, 0, NULL));

		/* BIG Create Sync with the minimum valid Num_BIS. */
		mock_ok();
		ATF_CHECK_EQ(0, hci_le_big_create_sync(FD, 0, 0x0001, 0, NULL, 0,
		    0x0064, 1, (uint8_t[]){ 1 }));
	}

ATF_TC_WITHOUT_HEAD(node_init_and_host_support_edges);
ATF_TC_BODY(node_init_and_host_support_edges, tc)
{

	/* hci_node_init success at verbose 0 and (verbose 2 x daemonized 0/1). */
	blued_verbose = 0;
	con_reset();
	ATF_CHECK_EQ(0, hci_node_init(FD));
	blued_verbose = 2;
	blued_daemonized = 0;
	con_reset();
	ATF_CHECK_EQ(0, hci_node_init(FD));
	blued_daemonized = 1;
	con_reset();
	ATF_CHECK_EQ(0, hci_node_init(FD));
	blued_daemonized = 0;

	/* hci_node_init: ioctl failure. */
	con_reset();
	G_ioctl_fail = 1;
	ATF_CHECK_EQ(-1, hci_node_init(FD));

	/* write_le_host_support: the opposite ternary operands (0,1). */
	mock_ok();
	ATF_CHECK_EQ(0, hci_write_le_host_support(FD, 0, 1));

	blued_verbose = 0;
}

/*
 * The two validation guards that emit a LOG_HCI on rejection
 * (hci_le_connection_update and hci_le_set_periodic_adv_params), re-driven
 * under verbose with blued_daemonized in {0,1} so the trace regions execute.
 */
ATF_TC_WITHOUT_HEAD(validation_verbose_logs);
ATF_TC_BODY(validation_verbose_logs, tc)
{
	int d;

	blued_verbose = 2;
	for (d = 0; d <= 1; d++) {
		blued_daemonized = d;
		mock_ok();
		(void)hci_le_connection_update(FD, 0x40, 0x0004, 0x0006, 0,
		    0x000A);				/* invalid interval */
		mock_ok();
		(void)hci_le_connection_update(FD, 0x40, 0x0006, 0x0006, 0x0200,
		    0x000A);				/* invalid latency */
		mock_ok();
		(void)hci_le_connection_update(FD, 0x40, 0x0006, 0x0006, 0,
		    0x0005);				/* invalid timeout */
		mock_ok();
		(void)hci_le_connection_update(FD, 0x40, 0x0C80, 0x0C80, 0,
		    0x000A);				/* timeout too short */
		mock_ok();
		(void)hci_le_set_periodic_adv_params(FD, 0, 0x0008, 0x0006, 0);
	}
	blued_verbose = 0;
	blued_daemonized = 0;
	ATF_CHECK(true);
}

/*
 * Remaining extended-scan receive-loop corner branches: EINTR continue, a
 * rejection of a legacy-in-ext report without its trailing RSSI octet, and
 * a non-0x0C params rejection status.
 */
ATF_TC_WITHOUT_HEAD(ext_scan_branch_corners);
ATF_TC_BODY(ext_scan_branch_corners, tc)
{
	struct ble_scan_result results[3];
	uint8_t a[6] = { 4, 4, 4, 4, 4, 4 };
	uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t ev[64], tev[8];
	int n, nres = -1;

	blued_verbose = 2;
	tev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	tev[1] = BT_CORE63_HCI_EVENT_LE_META;
	tev[2] = 1;
	tev[3] = BT_CORE63_HCI_LE_SCAN_TIMEOUT_SUBEVENT;

	recv_reset();
	recv_push_err(EAGAIN);			/* EAGAIN -> continue */
	recv_push_err(EINTR);			/* EINTR -> continue */
	/* An ignored (unknown) subevent while non-verbose is covered elsewhere;
	 * here verbose is on so the trace arm runs. */
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = 0x7E;				/* unknown subevent -> ignored */
	recv_push_data(ev, 4);
	/* legacy-in-ext report, random addr_type, no RSSI octet. */
	n = legacy_adv_event_norssi(ev, a, 0x01, ad, sizeof(ad));
	recv_push_data(ev, n);
	recv_push_data(tev, 4);			/* SCAN_TIMEOUT -> break */
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 3, &nres, 0x01));
	ATF_CHECK_EQ(0, nres);

	/* Non-0x0C params rejection at setparams -> the (status==0x0C) False. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 1;
	R.seq_status[0] = 0x11;
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_ext_scan(FD, 1, results, 3, &nres, 0x01));

	/* Ignored subevent while NON-verbose -> the (blued_verbose>=2) False arm. */
	blued_verbose = 0;
	recv_reset();
	ev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[1] = BT_CORE63_HCI_EVENT_LE_META;
	ev[2] = 1;
	ev[3] = 0x7E;
	recv_push_data(ev, 4);
	recv_push_data(tev, 4);
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 3, &nres, 0x01));
}

/*
 * Final extended-scan corner branches: Coded-PHY-only scanning_phys (the
 * "& 0x01" False arm), a two-report legacy meta with maxresults==1 (the inner
 * count<max False), the 0x0C-retry path where the intermediate disable itself
 * returns a non-zero status (the retry disable-status trace), and the
 * wall-clock loop-exit (the while(time<end_time) False arm).
 */
ATF_TC_WITHOUT_HEAD(ext_scan_final_corners);
ATF_TC_BODY(ext_scan_final_corners, tc)
{
	struct ble_scan_result results[2];
	uint8_t a[6] = { 5, 5, 5, 5, 5, 5 };
	uint8_t b[6] = { 6, 6, 6, 6, 6, 6 };
	uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t ev[128], tev[8];
	int nres = -1, i, k;

	blued_verbose = 2;
	tev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	tev[1] = BT_CORE63_HCI_EVENT_LE_META;
	tev[2] = 1;
	tev[3] = BT_CORE63_HCI_LE_SCAN_TIMEOUT_SUBEVENT;

	/* scanning_phys = Coded only (0x04): the "& 0x01" False, "& 0x04" True. */
	recv_reset();
	recv_push_data(tev, 4);
	mock_ok();
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x04));

	/* Two legacy reports in one meta with maxresults == 1 (inner count<max). */
	recv_reset();
	i = 0;
	ev[i++] = BT_CORE63_HCI_H4_EVENT_PACKET;
	ev[i++] = BT_CORE63_HCI_EVENT_LE_META;
	ev[i++] = 0;
	ev[i++] = BT_CORE63_HCI_LE_ADV_REPORT_SUBEVENT;
	ev[i++] = 2;
	for (k = 0; k < 2; k++) {
		ev[i++] = 0x00;
		ev[i++] = 0x00;
		memcpy(ev + i, k == 0 ? a : b, 6); i += 6;
		ev[i++] = (uint8_t)sizeof(ad);
		memcpy(ev + i, ad, sizeof(ad)); i += sizeof(ad);
		ev[i++] = (uint8_t)(-40);
	}
	ev[2] = (uint8_t)(i - 3);
	recv_push_data(ev, i);
	recv_push_data(tev, 4);
	mock_ok();
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 1, &nres, 0x01));
	ATF_CHECK_EQ(1, nres);

	/* 0x0C retry where the intermediate disable returns status != 0. */
	recv_reset();
	recv_push_data(tev, 4);
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 8;
	R.seq_status[0] = 0x0C;			/* params rejected */
	R.seq_status[1] = 0x0C;			/* disable status != 0 (trace) */
	R.seq_status[2] = 0x00;			/* params retry ok */
	R.seq_status[3] = 0x00;			/* enable ok */
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));

	/* Wall-clock loop exit: no events ever arrive (EAGAIN forever). */
	recv_reset();
	Recv_eagain_forever = 1;
	mock_ok();
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 0, results, 2, &nres, 0x01));
	Recv_eagain_forever = 0;
	ATF_CHECK_EQ(0, nres);

	/*
	 * Extended report with addr_type 0x03 (resolvable-random) exercises the
	 * second operand of (addr_type == 0x01 || addr_type == 0x03) in
	 * hci_parse_ext_adv_report.
	 */
	recv_reset();
	i = ext_adv_event(ev, a, ad, sizeof(ad));
	ev[7] = 0x03;
	recv_push_data(ev, i);
	recv_push_data(tev, 4);
	mock_ok();
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));
	ATF_CHECK_EQ(BDADDR_LE_RANDOM, results[0].addr_type);

	/*
	 * Re-drive the report-processing and 0x0C-retry paths NON-verbose so the
	 * (blued_verbose >= lvl) False arm of each of those LOG sites is taken.
	 */
	blued_verbose = 0;
	recv_reset();
	i = ext_adv_event(ev, b, ad, sizeof(ad));
	recv_push_data(ev, i);			/* one extended report */
	recv_push_data(tev, 4);
	mock_ok();
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));

	recv_reset();
	recv_push_data(tev, 4);
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 8;
	R.seq_status[0] = 0x0C;			/* params rejected */
	R.seq_status[1] = 0x0C;			/* disable status != 0 */
	R.seq_status[2] = 0x00;			/* retry ok */
	R.seq_status[3] = 0x00;			/* enable ok */
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 2, &nres, 0x01));

	blued_verbose = 0;
}

/*
 * Remaining hci_le_ext_scan MC/DC operand arms: a recv error whose errno is
 * neither EAGAIN nor EINTR (the EINTR-operand False -> break), two distinct
 * then a duplicate legacy-in-ext address (the dedup memcmp both arms and the
 * !dup False arm), and a 0x0C retry where the intermediate disable and the
 * retry itself fail at the transport (the "== 0" operand False arms).
 */
ATF_TC_WITHOUT_HEAD(ext_scan_dedup_and_retry_fail);
ATF_TC_BODY(ext_scan_dedup_and_retry_fail, tc)
{
	struct ble_scan_result results[4];
	uint8_t a[6] = { 10, 0, 0, 0, 0, 1 };
	uint8_t b[6] = { 10, 0, 0, 0, 0, 2 };
	uint8_t ad[] = { 0x02, 0x01, 0x06 };
	uint8_t ev[64], tev[8];
	int n, nres = -1;

	tev[0] = BT_CORE63_HCI_H4_EVENT_PACKET;
	tev[1] = BT_CORE63_HCI_EVENT_LE_META;
	tev[2] = 1;
	tev[3] = BT_CORE63_HCI_LE_SCAN_TIMEOUT_SUBEVENT;

	/* Distinct legacy addrs a,b then a duplicate a; ends with SCAN_TIMEOUT. */
	recv_reset();
	n = legacy_adv_event(ev, a, 0, ad, sizeof(ad), -40);
	recv_push_data(ev, n);
	n = legacy_adv_event(ev, b, 0, ad, sizeof(ad), -41);
	recv_push_data(ev, n);			/* distinct -> memcmp != 0 arm */
	n = legacy_adv_event(ev, a, 0, ad, sizeof(ad), -42);
	recv_push_data(ev, n);			/* duplicate -> memcmp == 0 arm */
	/* an extended duplicate of b -> the ext !dup False arm. */
	n = ext_adv_event(ev, b, ad, sizeof(ad));
	recv_push_data(ev, n);
	recv_push_data(tev, 4);
	mock_ok();
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 4, &nres, 0x01));
	ATF_CHECK_EQ(2, nres);

	/* recv error errno=EIO (neither EAGAIN nor EINTR) -> break. */
	recv_reset();
	recv_push_err(EIO);
	mock_ok();
	nres = -1;
	ATF_CHECK_EQ(0, hci_le_ext_scan(FD, 1, results, 4, &nres, 0x01));

	/* 0x0C retry where the disable and the retry both transport-fail. */
	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 3;
	R.seq_status[0] = 0x0C;			/* params rejected */
	R.seq_fail[1] = 1;			/* disable bt_devreq < 0 */
	R.seq_fail[2] = 1;			/* retry params bt_devreq < 0 */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_ext_scan(FD, 1, results, 4, &nres, 0x01));
}

/*
 * hci_le_scan: a non-0x0C params rejection exercises the (status == 0x0C)
 * False arm at hci_scan.c:218.
 */
ATF_TC_WITHOUT_HEAD(le_scan_params_reject_noncmddisallowed);
ATF_TC_BODY(le_scan_params_reject_noncmddisallowed, tc)
{
	struct ble_scan_result results[2];
	int nres = -1;

	recv_reset();
	memset(&R, 0, sizeof(R));
	R.use_seq = 1;
	R.seq_len = 2;
	R.seq_status[0] = 0x00;			/* pre-scan disable ok */
	R.seq_status[1] = 0x12;			/* params rejected, != 0x0C */
	errno = 0;
	ATF_CHECK_EQ(-1, hci_le_scan(FD, 1, results, 2, &nres));
	ATF_CHECK_EQ(EIO, errno);
}

/* ================================================================
 * ATF program entry point.
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, verbose_log_sweep);
	ATF_TP_ADD_TC(tp, reject_arm_maps_to_eio);
	ATF_TP_ADD_TC(tp, validation_adv);
	ATF_TP_ADD_TC(tp, validation_conn);
	ATF_TP_ADD_TC(tp, validation_misc_privacy);
	ATF_TP_ADD_TC(tp, disconnect_arms);
	ATF_TP_ADD_TC(tp, send_raw_cmd_plen);
	ATF_TP_ADD_TC(tp, get_con_handle_arms);
	ATF_TP_ADD_TC(tp, conn_param_update_req);
	ATF_TP_ADD_TC(tp, wait_encryption_arms);
	ATF_TP_ADD_TC(tp, le_scan_report_merge);
	ATF_TP_ADD_TC(tp, le_scan_setup_errors);
	ATF_TP_ADD_TC(tp, le_scan_malformed_reports);
	ATF_TP_ADD_TC(tp, le_scan_branch_corners);
	ATF_TP_ADD_TC(tp, ext_scan_reports);
	ATF_TP_ADD_TC(tp, ext_scan_long_duration_and_final_disable_fail);
	ATF_TP_ADD_TC(tp, ext_scan_timeout_and_ignored);
	ATF_TP_ADD_TC(tp, ext_scan_setup_errors);
	ATF_TP_ADD_TC(tp, scan_daemonized_log_sweep);
	ATF_TP_ADD_TC(tp, coc_connect_arms);
	ATF_TP_ADD_TC(tp, ecbfc_connect_arms);
	ATF_TP_ADD_TC(tp, ecbfc_reconfig_arms);
	ATF_TP_ADD_TC(tp, iso_connect_socket_arms);
	ATF_TP_ADD_TC(tp, devreq_logging_paths);
	ATF_TP_ADD_TC(tp, hci_log_edges);
	ATF_TP_ADD_TC(tp, read_cmd_null_outparams);
	ATF_TP_ADD_TC(tp, cte_pattern_validation_and_iso_edges);
	ATF_TP_ADD_TC(tp, node_init_and_host_support_edges);
	ATF_TP_ADD_TC(tp, validation_verbose_logs);
	ATF_TP_ADD_TC(tp, ext_scan_branch_corners);
	ATF_TP_ADD_TC(tp, ext_scan_final_corners);
	ATF_TP_ADD_TC(tp, ext_scan_dedup_and_retry_fail);
	ATF_TP_ADD_TC(tp, le_scan_params_reject_noncmddisallowed);
	ATF_TP_ADD_TC(tp, devreq_logged_response_variants);
	ATF_TP_ADD_TC(tp, enable_ternary_disabled_arm);

	return (atf_no_error());
}
