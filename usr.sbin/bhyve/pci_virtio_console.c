/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 iXsystems Inc.
 * All rights reserved.
 *
 * This software was developed by Jakub Klama <jceel@FreeBSD.org>
 * under sponsorship from iXsystems Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/endian.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/linker_set.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <err.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <pthread_np.h>
#include <libgen.h>
#include <sysexits.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "iov.h"
#include "pci_emul.h"
#include "virtio.h"
#include "virtio_pci_modern_probes.h"
#include "mevent.h"
#ifdef BHYVE_SNAPSHOT
#include "snapshot.h"
#endif
#include "sockstream.h"

#define	VTCON_RINGSZ	64
#define	VTCON_MAXPORTS	16
#define	VTCON_MAXQ	(VTCON_MAXPORTS * 2 + 2)
#define	VTCON_SOCK_TX_MAX	(1024 * 1024)
#define	VTCON_SOCK_TX_INITIAL	4096

#define	VTCON_DEVICE_READY	0
#define	VTCON_DEVICE_ADD	1
#define	VTCON_DEVICE_REMOVE	2
#define	VTCON_PORT_READY	3
#define	VTCON_CONSOLE_PORT	4
#define	VTCON_CONSOLE_RESIZE	5
#define	VTCON_PORT_OPEN		6
#define	VTCON_PORT_NAME		7

#define	VTCON_F_SIZE		0
#define	VTCON_F_MULTIPORT	1
#define	VTCON_F_EMERG_WRITE	2
#define	VTCON_S_HOSTCAPS	\
    (1ULL << VTCON_F_SIZE | 1ULL << VTCON_F_MULTIPORT | \
    1ULL << VTCON_F_EMERG_WRITE)

static int pci_vtcon_debug;
#define DPRINTF(params) if (pci_vtcon_debug) PRINTLN params
#define WPRINTF(params) PRINTLN params

struct pci_vtcon_softc;
struct pci_vtcon_port;
struct pci_vtcon_config;
typedef void (pci_vtcon_cb_t)(struct pci_vtcon_port *, void *, struct iovec *,
    int);
typedef void (pci_vtcon_rx_cb_t)(struct pci_vtcon_port *, void *);

struct pci_vtcon_port {
	struct pci_vtcon_softc * vsp_sc;
	int                      vsp_id;
	const char *             vsp_name;
	bool                     vsp_enabled;
	bool                     vsp_console;
	bool                     vsp_rx_ready;
	bool                     vsp_open;
	bool                     vsp_announced;
	bool                     vsp_guest_ready;
	bool                     vsp_named;
	bool                     vsp_console_pending;
	bool                     vsp_open_pending;
	int                      vsp_rxq;
	int                      vsp_txq;
	void *                   vsp_arg;
	pci_vtcon_cb_t *         vsp_cb;
	pci_vtcon_rx_cb_t *      vsp_rx_cb;
	pci_vtcon_rx_cb_t *      vsp_rx_disable_cb;
};

struct pci_vtcon_sock
{
	struct pci_vtcon_softc * vss_sc;
	struct pci_vtcon_port *  vss_port;
	const char *             vss_path;
	struct mevent *          vss_server_evp;
	struct mevent *          vss_conn_evp;
	struct mevent *          vss_write_evp;
	int                      vss_server_fd;
	int                      vss_conn_fd;
	bool                     vss_open;
	uint8_t *                vss_tx_buf;
	size_t                   vss_tx_off;
	size_t                   vss_tx_len;
	size_t                   vss_tx_cap;
};

struct pci_vtcon_softc {
	struct virtio_softc      vsc_vs;
	struct virtio_consts     vsc_consts;
	struct vqueue_info       vsc_queues[VTCON_MAXQ];
	pthread_mutex_t          vsc_mtx;
	uint64_t                 vsc_features;
	bool                     vsc_ready;
	bool                     vsc_intr_initialized;
	bool                     vsc_mtx_initialized;
	struct pci_vtcon_port    vsc_control_port;
 	struct pci_vtcon_port    vsc_ports[VTCON_MAXPORTS];
	struct pci_vtcon_config *vsc_config;
};

struct pci_vtcon_config {
	uint16_t cols;
	uint16_t rows;
	uint32_t max_nr_ports;
	uint32_t emerg_wr;
} __attribute__((packed));

struct pci_vtcon_control {
	uint32_t id;
	uint16_t event;
	uint16_t value;
} __attribute__((packed));

struct pci_vtcon_console_resize {
	uint16_t cols;
	uint16_t rows;
} __attribute__((packed));

static uint16_t pci_vtcon_encode16(const struct pci_vtcon_softc *, uint16_t);
static uint32_t pci_vtcon_encode32(const struct pci_vtcon_softc *, uint32_t);
static uint16_t pci_vtcon_decode16(const struct pci_vtcon_softc *, uint16_t);
static uint32_t pci_vtcon_decode32(const struct pci_vtcon_softc *, uint32_t);
static void pci_vtcon_reset(void *);
static int pci_vtcon_qreset(void *, struct vqueue_info *, uint64_t);
static inline struct pci_vtcon_port *pci_vtcon_vq_to_port(
    struct pci_vtcon_softc *, struct vqueue_info *);
static void pci_vtcon_notify_rx(void *, struct vqueue_info *);
static void pci_vtcon_notify_tx(void *, struct vqueue_info *);
static int pci_vtcon_cfgread(void *, int, int, uint32_t *);
static int pci_vtcon_cfgwrite(void *, int, int, uint32_t);
static int pci_vtcon_neg_features(void *, uint64_t);
static void pci_vtcon_sock_accept(int, enum ev_type,  void *);
static void pci_vtcon_sock_rx(int, enum ev_type, void *);
static void pci_vtcon_sock_tx_event(int, enum ev_type, void *);
static void pci_vtcon_sock_tx(struct pci_vtcon_port *, void *, struct iovec *,
    int);
static void pci_vtcon_sock_rx_enable(struct pci_vtcon_port *, void *);
static void pci_vtcon_sock_rx_disable(struct pci_vtcon_port *, void *);
static void pci_vtcon_sock_close(struct pci_vtcon_sock *);
static bool pci_vtcon_control_send(struct pci_vtcon_softc *,
    struct pci_vtcon_control *, const void *, size_t);
static bool pci_vtcon_announce_port(struct pci_vtcon_port *);
static void pci_vtcon_open_port(struct pci_vtcon_port *, bool);
static void pci_vtcon_destroy(struct pci_vtcon_softc *);
static int pci_vtcon_suspend_device(void *);
static int pci_vtcon_resume_device(void *);
static void pci_vtcon_resume_complete(void *);
#ifdef BHYVE_SNAPSHOT
static int pci_vtcon_pause(void *);
static int pci_vtcon_resume(void *);
static int pci_vtcon_snapshot(void *, struct vm_snapshot_meta *);
static int pci_vtcon_snapshot_validate(struct vm_snapshot_meta *);
#endif

static struct virtio_consts vtcon_vi_consts = {
	.vc_name =	"vtcon",
	.vc_nvq =	VTCON_MAXQ,
	.vc_cfgsize =	sizeof(struct pci_vtcon_config),
	.vc_reset =	pci_vtcon_reset,
	.vc_cfgread =	pci_vtcon_cfgread,
	.vc_cfgwrite =	pci_vtcon_cfgwrite,
	.vc_apply_features = pci_vtcon_neg_features,
	.vc_qreset =	pci_vtcon_qreset,
	.vc_suspend =	pci_vtcon_suspend_device,
	.vc_resume_device = pci_vtcon_resume_device,
	.vc_resume_complete = pci_vtcon_resume_complete,
	.vc_hv_caps =	VTCON_S_HOSTCAPS | VIRTIO_F_IN_ORDER |
	    VIRTIO_F_RING_RESET | VIRTIO_F_SUSPEND,
#ifdef BHYVE_SNAPSHOT
	.vc_pause =	pci_vtcon_pause,
	.vc_resume =	pci_vtcon_resume,
	.vc_snapshot =	pci_vtcon_snapshot,
#endif
};

static int
pci_vtcon_suspend_device(void *vsc __unused)
{

	/*
	 * Every descriptor path and host event callback is serialized by
	 * vs_mtx.  The common lifecycle code has already published the queue
	 * fence before entering here, so callbacks that run later can retain
	 * host connection state but cannot acquire another guest descriptor.
	 */
	return (0);
}

static int
pci_vtcon_resume_device(void *vsc __unused)
{

	return (0);
}

static void
pci_vtcon_resume_complete(void *vsc)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_port *port;
	struct vqueue_info *vq;
	bool already_locked;
	int i;

	sc = vsc;
	/*
	 * A host read event observed during suspend disables itself after it
	 * sees the fenced receive queue.  Do not depend on a new guest kick:
	 * descriptors made available before suspend remain valid after resume.
	 * The control receive queue is included so connection and port changes
	 * retained while suspended are published promptly.
	 *
	 * Guest resume invokes this callback from the status-write path with
	 * vsc_mtx held.  Checkpoint resume invokes it after the backend resume
	 * callback has released that mutex.  Queue inspection and callback
	 * rearming must be serialized in both cases.
	 */
	already_locked = pthread_mutex_isowned_np(&sc->vsc_mtx);
	if (!already_locked)
		VS_LOCK(&sc->vsc_vs);
	if ((sc->vsc_features & (1ULL << VTCON_F_MULTIPORT)) != 0)
		pci_vtcon_notify_rx(sc,
		    &sc->vsc_queues[sc->vsc_control_port.vsp_txq]);
	for (i = 0; i < VTCON_MAXPORTS; i++) {
		port = &sc->vsc_ports[i];
		if (!port->vsp_enabled)
			continue;
		/*
		 * vsp_txq is the device-to-driver queue: pci_vtcon_sock_rx()
		 * consumes its writable buffers when host input arrives.
		 * vsp_rxq carries driver-to-device output and cannot rearm the
		 * host read callback.
		 */
		vq = &sc->vsc_queues[port->vsp_txq];
		if (vq_has_descs(vq))
			pci_vtcon_notify_rx(sc, vq);
	}
	if (!already_locked)
		VS_UNLOCK(&sc->vsc_vs);
}

static uint16_t
pci_vtcon_encode16(const struct pci_vtcon_softc *sc, uint16_t value)
{

	return (vi_pci_is_modern(&sc->vsc_vs) ? htole16(value) : value);
}

static uint32_t
pci_vtcon_encode32(const struct pci_vtcon_softc *sc, uint32_t value)
{

	return (vi_pci_is_modern(&sc->vsc_vs) ? htole32(value) : value);
}

static uint16_t
pci_vtcon_decode16(const struct pci_vtcon_softc *sc, uint16_t value)
{

	return (vi_pci_is_modern(&sc->vsc_vs) ? le16toh(value) : value);
}

static uint32_t
pci_vtcon_decode32(const struct pci_vtcon_softc *sc, uint32_t value)
{

	return (vi_pci_is_modern(&sc->vsc_vs) ? le32toh(value) : value);
}

static void
pci_vtcon_reset(void *vsc)
{
	struct pci_vtcon_softc *sc;
	int i;

	sc = vsc;

	DPRINTF(("vtcon: device reset requested!"));
	vi_reset_dev(&sc->vsc_vs);
	sc->vsc_features = 0;
	sc->vsc_ready = false;
	for (i = 0; i < VTCON_MAXPORTS; i++) {
		sc->vsc_ports[i].vsp_rx_ready = false;
		sc->vsc_ports[i].vsp_announced = false;
		sc->vsc_ports[i].vsp_guest_ready = false;
		sc->vsc_ports[i].vsp_named = false;
		sc->vsc_ports[i].vsp_console_pending = false;
		sc->vsc_ports[i].vsp_open_pending = false;
	}
}

static int
pci_vtcon_qreset(void *vsc, struct vqueue_info *vq,
    uint64_t generation __unused)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_port *port;

	sc = vsc;
	if (vq->vq_num >= VTCON_MAXQ)
		return (EINVAL);

	/*
	 * Descriptor processing and socket-buffer staging are synchronous while
	 * vsc_mtx is held.  A receive queue additionally carries an external
	 * readiness latch; clear it so no host input is associated with the old
	 * queue incarnation.  The socket callback will disable its read event if
	 * it is already pending, and a later guest kick re-enables it.
	 */
	if ((vq->vq_num & 1) == 0) {
		port = pci_vtcon_vq_to_port(sc, vq);
		port->vsp_rx_ready = false;
		if (port->vsp_rx_disable_cb != NULL)
			port->vsp_rx_disable_cb(port, port->vsp_arg);
	}
	return (0);
}

static int
pci_vtcon_neg_features(void *vsc, uint64_t negotiated_features)
{
	struct pci_vtcon_softc *sc = vsc;
	int i;

	sc->vsc_features = negotiated_features;
	if ((negotiated_features & (1ULL << VTCON_F_MULTIPORT)) == 0) {
		sc->vsc_ready = false;
		for (i = 0; i < VTCON_MAXPORTS; i++) {
			sc->vsc_ports[i].vsp_announced = false;
			sc->vsc_ports[i].vsp_guest_ready = false;
			sc->vsc_ports[i].vsp_named = false;
			sc->vsc_ports[i].vsp_console_pending = false;
			sc->vsc_ports[i].vsp_open_pending = false;
		}
	}
	return (0);
}

static bool
pci_vtcon_queue_active(const struct pci_vtcon_softc *sc, uint16_t qnum)
{

	/*
	 * Port 0 always has receive and transmit queues.  The two control
	 * queues and every additional port queue are enabled only when the
	 * driver negotiated VIRTIO_CONSOLE_F_MULTIPORT (VirtIO 1.4 5.3.5).
	 */
	return (qnum < 2 ||
	    (sc->vsc_features & (1ULL << VTCON_F_MULTIPORT)) != 0);
}

static int
pci_vtcon_cfgread(void *vsc, int offset, int size, uint32_t *retval)
{
	struct pci_vtcon_softc *sc = vsc;
	int error;

	/*
	 * The modern device configuration is a little-endian byte stream.  Do
	 * not memcpy a short field into a host uint32_t: that places it in the
	 * high bytes on a big-endian host and makes even byte-sized accesses
	 * host-layout dependent.  Explicit legacy mode is intentionally kept
	 * only for little-endian compatibility guests, so the same decoder is
	 * correct for every supported bhyve host.
	 */
	error = vi_config_read_le(sc->vsc_config, sizeof(*sc->vsc_config),
	    offset, size, retval);
	return (error == 0 ? 0 : -1);
}

static int
pci_vtcon_cfgwrite(void *vsc, int offset, int size, uint32_t val)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_port *port;
	struct iovec iov;
	uint8_t ch;

	sc = vsc;
	if (offset != offsetof(struct pci_vtcon_config, emerg_wr) ||
	    size != sizeof(sc->vsc_config->emerg_wr))
		return (-1);

	/*
	 * VIRTIO_CONSOLE_F_EMERG_WRITE is usable before feature negotiation and
	 * before virtqueues are configured.  Route its low byte through port
	 * zero's ordinary backend callback so it observes the same buffering,
	 * disconnect, and error handling as queued console output.
	 */
	sc->vsc_config->emerg_wr = pci_vtcon_encode32(sc, val);
	port = &sc->vsc_ports[0];
	if (port->vsp_enabled && port->vsp_cb != NULL) {
		ch = val;
		iov = (struct iovec){ .iov_base = &ch, .iov_len = sizeof(ch) };
		port->vsp_cb(port, port->vsp_arg, &iov, 1);
		VIRTIO_PROBE_CONSOLE_EMERGENCY_WRITE(
		    sc->vsc_consts.vc_name, ch, 1);
	} else {
		VIRTIO_PROBE_CONSOLE_EMERGENCY_WRITE(
		    sc->vsc_consts.vc_name, (uint8_t)val, 0);
	}
	return (0);
}

static inline struct pci_vtcon_port *
pci_vtcon_vq_to_port(struct pci_vtcon_softc *sc, struct vqueue_info *vq)
{
	uint16_t num = vq->vq_num;

	if (num == 0 || num == 1)
		return (&sc->vsc_ports[0]);

	if (num == 2 || num == 3)
		return (&sc->vsc_control_port);

	return (&sc->vsc_ports[(num / 2) - 1]);
}

static inline struct vqueue_info *
pci_vtcon_port_to_vq(struct pci_vtcon_port *port, bool tx_queue)
{
	int qnum;

	qnum = tx_queue ? port->vsp_txq : port->vsp_rxq;
	return (&port->vsp_sc->vsc_queues[qnum]);
}

static struct pci_vtcon_port *
pci_vtcon_port_add(struct pci_vtcon_softc *sc, int port_id, const char *name,
    pci_vtcon_cb_t *cb, pci_vtcon_rx_cb_t *rx_cb,
    pci_vtcon_rx_cb_t *rx_disable_cb, void *arg)
{
	struct pci_vtcon_port *port;

	port = &sc->vsc_ports[port_id];
	if (port->vsp_enabled) {
		errno = EBUSY;
		return (NULL);
	}
	port->vsp_id = port_id;
	port->vsp_sc = sc;
	port->vsp_name = name;
	port->vsp_cb = cb;
	port->vsp_rx_cb = rx_cb;
	port->vsp_rx_disable_cb = rx_disable_cb;
	port->vsp_arg = arg;

	if (port->vsp_id == 0) {
		/* port0 */
		port->vsp_txq = 0;
		port->vsp_rxq = 1;
	} else {
		port->vsp_txq = (port_id + 1) * 2;
		port->vsp_rxq = port->vsp_txq + 1;
	}

	port->vsp_enabled = true;
	return (port);
}

static int
pci_vtcon_parse_port(const char *value, int *port, const char **errstr)
{
	long long parsed;
	const unsigned char *cp;

	*errstr = NULL;
	if (value == NULL || value[0] == '\0') {
		*errstr = "invalid";
		return (EINVAL);
	}
	for (cp = (const unsigned char *)value; *cp != '\0'; cp++) {
		if (!isdigit(*cp)) {
			*errstr = "invalid";
			return (EINVAL);
		}
	}
	parsed = strtonum(value, 0, VTCON_MAXPORTS - 1, errstr);
	if (*errstr != NULL)
		return (EINVAL);
	*port = (int)parsed;
	return (0);
}

static int
pci_vtcon_sock_add(struct pci_vtcon_softc *sc, const char *port_name,
    const nvlist_t *nvl)
{
	struct pci_vtcon_sock *sock = NULL;
	struct sockaddr_un sun;
	const char *errstr, *name, *path;
	char *pathcopy;
	int port;
	bool bound = false;
	int s = -1, fd = -1, error = 0;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	if (pci_vtcon_parse_port(port_name, &port, &errstr) != 0) {
		EPRINTLN("vtcon: Invalid port %s: %s", port_name, errstr);
		error = -1;
		goto out;
	}

	path = get_config_value_node(nvl, "path");
	if (path == NULL) {
		EPRINTLN("vtcon: required path missing for port %d", port);
		error = -1;
		goto out;
	}
	name = get_config_value_node(nvl, "name");
	if (name == NULL) {
		EPRINTLN("vtcon: required name missing for port %d", port);
		error = -1;
		goto out;
	}

	sock = calloc(1, sizeof(struct pci_vtcon_sock));
	if (sock == NULL) {
		error = -1;
		goto out;
	}
	sock->vss_sc = sc;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		error = -1;
		goto out;
	}

	pathcopy = strdup(path);
	if (pathcopy == NULL) {
		error = -1;
		goto out;
	}

	fd = open(dirname(pathcopy), O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		free(pathcopy);
		error = -1;
		goto out;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(struct sockaddr_un);
	strcpy(pathcopy, path);
	if (strlcpy(sun.sun_path, basename(pathcopy), sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		free(pathcopy);
		errno = ENAMETOOLONG;
		error = -1;
		goto out;
	}
	free(pathcopy);

	if (bindat(fd, s, (struct sockaddr *)&sun, sun.sun_len) < 0) {
		error = -1;
		goto out;
	}
	bound = true;

	if (fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
		error = -1;
		goto out;
	}

	if (listen(s, 1) < 0) {
		error = -1;
		goto out;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(s, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	sock->vss_open = false;
	sock->vss_path = path;
	sock->vss_conn_fd = -1;
	sock->vss_server_fd = s;
	sock->vss_server_evp = mevent_add(s, EVF_READ, pci_vtcon_sock_accept,
	    sock);

	if (sock->vss_server_evp == NULL) {
		error = -1;
		goto out;
	}
	sock->vss_port = pci_vtcon_port_add(sc, port, name, pci_vtcon_sock_tx,
	    pci_vtcon_sock_rx_enable, pci_vtcon_sock_rx_disable, sock);
	if (sock->vss_port == NULL) {
		error = -1;
		goto out;
	}
	sock->vss_port->vsp_console =
	    get_config_bool_node_default(nvl, "console", false);

out:
	if (error != 0 && bound)
		unlinkat(fd, sun.sun_path, 0);
	if (fd != -1)
		close(fd);

	if (error != 0) {
		if (sock != NULL && sock->vss_server_evp != NULL) {
			(void)mevent_delete_sync(sock->vss_server_evp);
			sock->vss_server_evp = NULL;
		}
		if (s != -1)
			close(s);
		free(sock);
	}

	return (error);
}

static void
pci_vtcon_destroy(struct pci_vtcon_softc *sc)
{
	struct pci_vtcon_sock *sock;
	int i;

	if (sc == NULL)
		return;
	for (i = 0; i < VTCON_MAXPORTS; i++) {
		if (!sc->vsc_ports[i].vsp_enabled ||
		    sc->vsc_ports[i].vsp_arg == NULL)
			continue;
		sock = sc->vsc_ports[i].vsp_arg;
		/*
		 * The ordinary close path runs on the event thread and therefore
		 * uses asynchronous deletion.  Device destruction frees sock, so
		 * it must first wait until no registered callback can retain that
		 * pointer.
		 */
		if (sock->vss_write_evp != NULL) {
			(void)mevent_delete_sync(sock->vss_write_evp);
			sock->vss_write_evp = NULL;
		}
		if (sock->vss_conn_evp != NULL) {
			(void)mevent_delete_sync(sock->vss_conn_evp);
			sock->vss_conn_evp = NULL;
		}
		if (sock->vss_conn_fd >= 0)
			close(sock->vss_conn_fd);
		if (sock->vss_server_evp != NULL) {
			(void)mevent_delete_sync(sock->vss_server_evp);
			sock->vss_server_evp = NULL;
		}
		if (sock->vss_server_fd >= 0)
			close(sock->vss_server_fd);
		if (sock->vss_path != NULL)
			unlink(sock->vss_path);
		free(sock->vss_tx_buf);
		free(sock);
	}
	free(sc->vsc_vs.vs_modern);
	if (sc->vsc_intr_initialized)
		pthread_mutex_destroy(&sc->vsc_vs.vs_isr_mtx);
	if (sc->vsc_mtx_initialized)
		pthread_mutex_destroy(&sc->vsc_mtx);
	free(sc->vsc_config);
	free(sc);
}

static void
pci_vtcon_sock_accept(int fd __unused, enum ev_type t __unused, void *arg)
{
	struct pci_vtcon_sock *sock = (struct pci_vtcon_sock *)arg;
	struct virtio_softc *vs;
	int s;

	/*
	 * Serialize accept itself with checkpoint pause.  Accepting a host
	 * connection before taking the device lock would hide an unportable fd
	 * from the pause-time reconstructibility check.
	 */
	vs = &sock->vss_sc->vsc_vs;
	VS_LOCK(vs);
	s = accept4(sock->vss_server_fd, NULL, NULL, SOCK_NONBLOCK);
	if (s < 0) {
		VS_UNLOCK(vs);
		return;
	}

	if (sock->vss_port == NULL || sock->vss_open) {
		VS_UNLOCK(vs);
		close(s);
		return;
	}
	sock->vss_conn_fd = s;
	sock->vss_conn_evp = mevent_add(s, EVF_READ, pci_vtcon_sock_rx, sock);
	if (sock->vss_conn_evp == NULL) {
		close(s);
		sock->vss_conn_fd = -1;
		VS_UNLOCK(vs);
		return;
	}
	sock->vss_write_evp = mevent_add_disabled(s, EVF_WRITE,
	    pci_vtcon_sock_tx_event, sock);
	if (sock->vss_write_evp == NULL) {
		mevent_delete_close(sock->vss_conn_evp);
		sock->vss_conn_evp = NULL;
		sock->vss_conn_fd = -1;
		VS_UNLOCK(vs);
		return;
	}
	sock->vss_open = true;

	pci_vtcon_open_port(sock->vss_port, true);
	VS_UNLOCK(vs);
}

static void
pci_vtcon_sock_close(struct pci_vtcon_sock *sock)
{
	if (sock->vss_write_evp != NULL)
		mevent_delete(sock->vss_write_evp);
	if (sock->vss_conn_evp != NULL)
		mevent_delete_close(sock->vss_conn_evp);
	else if (sock->vss_conn_fd >= 0)
		close(sock->vss_conn_fd);
	sock->vss_conn_evp = NULL;
	sock->vss_write_evp = NULL;
	sock->vss_conn_fd = -1;
	sock->vss_open = false;
	free(sock->vss_tx_buf);
	sock->vss_tx_buf = NULL;
	sock->vss_tx_off = 0;
	sock->vss_tx_len = 0;
	sock->vss_tx_cap = 0;
	pci_vtcon_open_port(sock->vss_port, false);
}

static void
pci_vtcon_sock_rx_enable(struct pci_vtcon_port *port __unused, void *arg)
{
	struct pci_vtcon_sock *sock = arg;

	if (sock->vss_open && sock->vss_conn_evp != NULL)
		mevent_enable(sock->vss_conn_evp);
}

static void
pci_vtcon_sock_rx_disable(struct pci_vtcon_port *port __unused, void *arg)
{
	struct pci_vtcon_sock *sock = arg;

	if (sock->vss_open && sock->vss_conn_evp != NULL)
		mevent_disable(sock->vss_conn_evp);
}

static void
pci_vtcon_sock_rx(int fd, enum ev_type t __unused, void *arg)
{
	struct pci_vtcon_port *port;
	struct pci_vtcon_sock *sock = (struct pci_vtcon_sock *)arg;
	struct virtio_softc *vs;
	struct vqueue_info *vq;
	struct vi_req req;
	struct iovec iov[VTCON_RINGSZ];
	uint16_t budget;
	int len, n;

	vs = &sock->vss_sc->vsc_vs;
	VS_LOCK(vs);
	/*
	 * mevent deletion is asynchronous on the dispatch thread, so an event
	 * selected for an old connection can remain in the current callback
	 * batch.  A later accept may already have installed a different
	 * connection in this persistent port object.  Never let the stale
	 * callback consume bytes or descriptors belonging to that session.
	 *
	 * Reuse of the same descriptor cannot race this check: mevent_add()
	 * rejects an fd/type tuple while the deleted registration remains on
	 * its change list.
	 */
	if (fd != sock->vss_conn_fd)
		goto out;
	port = sock->vss_port;
	if (port == NULL)
		goto out;
	vq = pci_vtcon_port_to_vq(port, true);

	if (!sock->vss_open)
		goto out;
	if (!port->vsp_rx_ready) {
		mevent_disable(sock->vss_conn_evp);
		goto out;
	}

	if (!vq_has_descs(vq)) {
		vq_kick_enable(vq);
		if (!vq_has_descs(vq)) {
			port->vsp_rx_ready = false;
			mevent_disable(sock->vss_conn_evp);
			vq_endchains(vq, 1);
			goto out;
		}
		vq_kick_disable(vq);
	}

	/*
	 * A confused guest can publish an arbitrarily advanced avail index whose
	 * entries all refer to malformed chains.  Bound one readiness callback to
	 * the negotiated queue capacity so it cannot monopolize the shared mevent
	 * thread without ever reaching the single host read below.
	 */
	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0)
			break;
		if (req.readable != 0 || req.writable != n) {
			WPRINTF(("vtcon: invalid receive descriptor chain"));
			vq_relchain_req(vq, &req, 0);
			continue;
		}
		len = readv(sock->vss_conn_fd, iov, n);

		if (len == 0 || (len < 0 && (errno == EAGAIN ||
		    errno == EWOULDBLOCK))) {
			vq_retchain_req(vq, &req);
			vq_endchains(vq, 0);
			if (len == 0)
				goto close;

			goto out;
		}
		if (len < 0) {
			vq_retchain_req(vq, &req);
			goto close;
		}

		vq_relchain_req(vq, &req, len);
		/* Process at most one read per readiness notification. */
		break;
	}

	vq_endchains(vq, !vq_has_descs(vq));
	goto out;

close:
	pci_vtcon_sock_close(sock);
out:
	VS_UNLOCK(vs);
}

static void
pci_vtcon_sock_drain(struct pci_vtcon_sock *sock)
{
	ssize_t n;

	if (!sock->vss_open || sock->vss_conn_fd < 0 ||
	    sock->vss_tx_off == sock->vss_tx_len)
		return;
	n = send(sock->vss_conn_fd, sock->vss_tx_buf + sock->vss_tx_off,
	    sock->vss_tx_len - sock->vss_tx_off, MSG_NOSIGNAL);
	if (n > 0) {
		sock->vss_tx_off += (size_t)n;
		if (sock->vss_tx_off == sock->vss_tx_len) {
			sock->vss_tx_off = 0;
			sock->vss_tx_len = 0;
			(void)mevent_disable(sock->vss_write_evp);
		} else
			(void)mevent_enable(sock->vss_write_evp);
		return;
	}
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	    errno == EINTR)) {
		(void)mevent_enable(sock->vss_write_evp);
		return;
	}
	pci_vtcon_sock_close(sock);
}

static void
pci_vtcon_sock_tx_event(int fd, enum ev_type type __unused, void *arg)
{
	struct pci_vtcon_sock *sock;
	struct virtio_softc *vs;

	sock = arg;
	vs = &sock->vss_sc->vsc_vs;
	VS_LOCK(vs);
	if (fd == sock->vss_conn_fd)
		pci_vtcon_sock_drain(sock);
	VS_UNLOCK(vs);
}

static void
pci_vtcon_sock_tx(struct pci_vtcon_port *port __unused, void *arg,
    struct iovec *iov, int niov)
{
	struct pci_vtcon_sock *sock;
	size_t cap, need, pending, total;
	uint8_t *buf;
	int i;

	sock = arg;
	if (!sock->vss_open || sock->vss_conn_fd < 0)
		return;

	total = 0;
	for (i = 0; i < niov; i++) {
		if (iov[i].iov_len > VTCON_SOCK_TX_MAX - total) {
			pci_vtcon_sock_close(sock);
			return;
		}
		total += iov[i].iov_len;
	}
	pending = sock->vss_tx_len - sock->vss_tx_off;
	if (total > VTCON_SOCK_TX_MAX - pending) {
		pci_vtcon_sock_close(sock);
		return;
	}
	if (sock->vss_tx_off != 0 &&
	    sock->vss_tx_cap - sock->vss_tx_len < total) {
		memmove(sock->vss_tx_buf, sock->vss_tx_buf + sock->vss_tx_off,
		    pending);
		sock->vss_tx_off = 0;
		sock->vss_tx_len = pending;
	}
	need = sock->vss_tx_len + total;
	if (need > sock->vss_tx_cap) {
		cap = MAX((size_t)VTCON_SOCK_TX_INITIAL, sock->vss_tx_cap);
		while (cap < need)
			cap = MIN(cap * 2, (size_t)VTCON_SOCK_TX_MAX);
		buf = realloc(sock->vss_tx_buf, cap);
		if (buf == NULL) {
			pci_vtcon_sock_close(sock);
			return;
		}
		sock->vss_tx_buf = buf;
		sock->vss_tx_cap = cap;
	}
	for (i = 0; i < niov; i++) {
		memcpy(sock->vss_tx_buf + sock->vss_tx_len,
		    iov[i].iov_base, iov[i].iov_len);
		sock->vss_tx_len += iov[i].iov_len;
	}
	pci_vtcon_sock_drain(sock);
}

static void
pci_vtcon_control_tx(struct pci_vtcon_port *port, void *arg __unused,
    struct iovec *iov, int niov)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_port *tmp;
	struct pci_vtcon_control ctrl, wire;
	size_t copied, len;
	int i;

	sc = port->vsp_sc;
	if (!pci_vtcon_queue_active(sc, port->vsp_rxq))
		return;
	/*
	 * Driver-to-device control messages contain exactly one control header;
	 * only device-to-driver messages such as PORT_NAME carry a payload.
	 * Reject both truncation and trailing bytes before decoding any field so
	 * an otherwise valid prefix cannot change device lifecycle state.
	 */
	if (niov < 0 || count_iov(iov, (size_t)niov) != sizeof(wire)) {
		WPRINTF(("vtcon: invalid control message length"));
		return;
	}
	copied = 0;
	for (i = 0; i < niov && copied < sizeof(wire); i++) {
		len = MIN(iov[i].iov_len, sizeof(wire) - copied);
		memcpy((uint8_t *)&wire + copied, iov[i].iov_base, len);
		copied += len;
	}
	if (copied != sizeof(wire)) {
		WPRINTF(("vtcon: short control message"));
		return;
	}
	ctrl.id = pci_vtcon_decode32(sc, wire.id);
	ctrl.event = pci_vtcon_decode16(sc, wire.event);
	ctrl.value = pci_vtcon_decode16(sc, wire.value);

	switch (ctrl.event) {
	case VTCON_DEVICE_READY:
		sc->vsc_ready = ctrl.value == 1;
		if (!sc->vsc_ready)
			break;
		/* set port ready events for registered ports */
		for (i = 0; i < VTCON_MAXPORTS; i++) {
			tmp = &sc->vsc_ports[i];
			if (tmp->vsp_enabled)
				(void)pci_vtcon_announce_port(tmp);
		}
		break;

	case VTCON_PORT_READY:
		if (ctrl.id >= VTCON_MAXPORTS) {
			WPRINTF(("VTCON_PORT_READY event for unknown port %u",
			    ctrl.id));
			return;
		}
		tmp = &sc->vsc_ports[ctrl.id];
		if (!sc->vsc_ready || !tmp->vsp_enabled ||
		    !tmp->vsp_announced || ctrl.value != 1) {
			WPRINTF(("VTCON_PORT_READY event for unavailable port %u",
			    ctrl.id));
			return;
		}

		tmp->vsp_guest_ready = true;
		if (tmp->vsp_console) {
			tmp->vsp_console_pending = true;
		}
		if (tmp->vsp_open)
			tmp->vsp_open_pending = true;
		(void)pci_vtcon_announce_port(tmp);
		break;
	}
}

static bool
pci_vtcon_announce_port(struct pci_vtcon_port *port)
{
	/* VIRTIO_ACTIVATION_ASSERTION: distinct-multiport-lifecycle */
	/* VIRTIO_ACTIVATION_ASSERTION: synchronous-fifo-port-and-control-completion */
	struct pci_vtcon_control event;

	event.id = port->vsp_id;
	event.event = VTCON_DEVICE_ADD;
	event.value = 1;
	if (!port->vsp_announced) {
		if (!pci_vtcon_control_send(port->vsp_sc, &event, NULL, 0))
			return (false);
		port->vsp_announced = true;
	}

	/*
	 * VirtIO 1.4 section 5.3.5 has the driver acknowledge DEVICE_ADD with
	 * PORT_READY before the device supplies additional port
	 * configuration.  Preserve pending host state until that acknowledgement
	 * arrives.
	 */
	if (!port->vsp_guest_ready)
		return (true);

	event.event = VTCON_PORT_NAME;
	if (!port->vsp_named) {
		if (!pci_vtcon_control_send(port->vsp_sc, &event,
		    port->vsp_name, strlen(port->vsp_name)))
			return (false);
		port->vsp_named = true;
	}
	if (port->vsp_console_pending) {
		/* VIRTIO_ACTIVATION_ASSERTION: console-port-nomination */
		event.event = VTCON_CONSOLE_PORT;
		if (!pci_vtcon_control_send(port->vsp_sc, &event, NULL, 0))
			return (false);
		port->vsp_console_pending = false;
	}
	if (port->vsp_open_pending) {
		event.event = VTCON_PORT_OPEN;
		event.value = (int)port->vsp_open;
		if (!pci_vtcon_control_send(port->vsp_sc, &event, NULL, 0))
			return (false);
		port->vsp_open_pending = false;
	}
	return (true);
}

static void
pci_vtcon_open_port(struct pci_vtcon_port *port, bool open)
{
	port->vsp_open = open;
	port->vsp_open_pending = true;
	if (!port->vsp_sc->vsc_ready) {
		return;
	}
	(void)pci_vtcon_announce_port(port);
}

static bool
pci_vtcon_control_send(struct pci_vtcon_softc *sc,
    struct pci_vtcon_control *ctrl, const void *payload, size_t len)
{
	struct pci_vtcon_control wire;
	struct vqueue_info *vq;
	struct vi_req req;
	struct iovec iov[VTCON_RINGSZ];
	uint8_t *msg;
	size_t msglen;
	uint32_t used;
	int n;

	if (len > SIZE_T_MAX - sizeof(struct pci_vtcon_control))
		return (false);
	msglen = sizeof(struct pci_vtcon_control) + len;

	vq = pci_vtcon_port_to_vq(&sc->vsc_control_port, true);

	if (!pci_vtcon_queue_active(sc, vq->vq_num))
		return (false);
	if (!vq_has_descs(vq))
		return (false);

	n = vq_getchain(vq, iov, nitems(iov), &req);
	if (n <= 0)
		return (false);
	used = 0;
	if (req.readable != 0 || req.writable != n ||
	    !check_iov_len(iov, n, msglen)) {
		WPRINTF(("vtcon: invalid control receive descriptor chain"));
		goto out;
	}

	msg = malloc(msglen);
	if (msg == NULL)
		goto out;
	wire.id = pci_vtcon_encode32(sc, ctrl->id);
	wire.event = pci_vtcon_encode16(sc, ctrl->event);
	wire.value = pci_vtcon_encode16(sc, ctrl->value);
	memcpy(msg, &wire, sizeof(wire));
	if (len > 0)
		memcpy(msg + sizeof(struct pci_vtcon_control), payload, len);
	used = buf_to_iov(msg, msglen, iov, n);
	free(msg);

out:
	vq_relchain_req(vq, &req, used);
	vq_endchains(vq, !vq_has_descs(vq));
	if (used == msglen)
		DPRINTF(("vtcon: control event=%u port=%u value=%u",
		    ctrl->event, ctrl->id, ctrl->value));
	return (used == msglen);
}


static void
pci_vtcon_notify_tx(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_port *port;
	struct iovec iov[VTCON_RINGSZ];
	struct vi_req req;
	uint16_t budget;
	int n;

	sc = vsc;
	if (!pci_vtcon_queue_active(sc, vq->vq_num))
		return;
	port = pci_vtcon_vq_to_port(sc, vq);

	budget = vq->vq_qsize;
	while (budget-- != 0 && vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0)
			break;
		if (req.writable != 0 || req.readable != n) {
			WPRINTF(("vtcon: invalid transmit descriptor chain"));
			vq_relchain_req(vq, &req, 0);
			continue;
		}
		if (port->vsp_enabled && port->vsp_cb != NULL)
			port->vsp_cb(port, port->vsp_arg, iov, n);

		/*
		 * Release this chain and handle more
		 */
		vq_relchain_req(vq, &req, 0);
	}
	vq_endchains(vq, !vq_has_descs(vq));
}

static void
pci_vtcon_notify_rx(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_port *port;
	int i;

	sc = vsc;
	if (!pci_vtcon_queue_active(sc, vq->vq_num))
		return;
	port = pci_vtcon_vq_to_port(sc, vq);

	/*
	 * A DEVICE_ADD and its PORT_NAME use distinct control receive
	 * buffers.  If the second buffer was temporarily unavailable, a new
	 * control receive kick must resume at PORT_NAME without replaying the
	 * already published DEVICE_ADD.
	 */
	if (port == &sc->vsc_control_port) {
		if (sc->vsc_ready) {
			for (i = 0; i < VTCON_MAXPORTS; i++) {
				port = &sc->vsc_ports[i];
				if (port->vsp_enabled &&
				    (!port->vsp_announced || !port->vsp_named ||
				    port->vsp_console_pending ||
				    port->vsp_open_pending))
					(void)pci_vtcon_announce_port(port);
			}
		}
		return;
	}

	if (port->vsp_enabled && !port->vsp_rx_ready) {
		port->vsp_rx_ready = 1;
		vq_kick_disable(vq);
		if (port->vsp_rx_cb != NULL)
			port->vsp_rx_cb(port, port->vsp_arg);
	}
}

/*
 * Each console device has a "port" node which contains nodes for
 * each port.  Ports are numbered starting at 0.
 */
static int
pci_vtcon_legacy_config_port(nvlist_t *nvl, int port, char *opt)
{
	char *name, *path;
	char node_name[sizeof("XX")];
	nvlist_t *port_nvl;

	name = strsep(&opt, "=");
	path = opt;
	if (path == NULL) {
		EPRINTLN("vtcon: port %s requires a path", name);
		return (-1);
	}
	if (port >= VTCON_MAXPORTS) {
		EPRINTLN("vtcon: too many ports");
		return (-1);
	}
	snprintf(node_name, sizeof(node_name), "%d", port);
	port_nvl = create_relative_config_node(nvl, node_name);
	set_config_value_node(port_nvl, "name", name);
	set_config_value_node(port_nvl, "path", path);
	return (0);
}

static int
pci_vtcon_legacy_config(nvlist_t *nvl, const char *opts)
{
	char *opt, *str, *tofree;
	char node_name[sizeof("XX")];
	const char *errstr;
	nvlist_t *ports_nvl;
	int console_port, error, port;

	if (opts == NULL)
		return (0);
	ports_nvl = create_relative_config_node(nvl, "port");
	tofree = str = strdup(opts);
	if (str == NULL)
		return (-1);
	error = 0;
	port = 0;
	while ((opt = strsep(&str, ",")) != NULL) {
		if (strcmp(opt, "transport=legacy") == 0 ||
		    strcmp(opt, "transport=modern") == 0) {
			set_config_value_node(nvl, "transport",
			    strchr(opt, '=') + 1);
			continue;
		}
		if (strcmp(opt, "packed=true") == 0 ||
		    strcmp(opt, "packed=false") == 0) {
			set_config_value_node(nvl, "packed",
			    strchr(opt, '=') + 1);
			continue;
		}
		if (strncmp(opt, "console-port=", sizeof("console-port=") - 1) ==
		    0) {
			if (pci_vtcon_parse_port(
			    opt + sizeof("console-port=") - 1, &console_port,
			    &errstr) != 0) {
				EPRINTLN("vtcon: invalid console port %s",
				    opt + sizeof("console-port=") - 1);
				error = -1;
				break;
			}
			snprintf(node_name, sizeof(node_name), "%d",
			    console_port);
			set_config_value_node(create_relative_config_node(
			    ports_nvl, node_name), "console", "true");
			continue;
		}
		error = pci_vtcon_legacy_config_port(ports_nvl, port, opt);
		if (error)
			break;
		port++;
	}
	if (error == 0) {
		for (int i = port; i < VTCON_MAXPORTS; i++) {
			snprintf(node_name, sizeof(node_name), "%d", i);
			if (find_relative_config_node(ports_nvl, node_name) !=
			    NULL) {
				EPRINTLN("vtcon: console port %d is not configured",
				    i);
				error = -1;
				break;
			}
		}
	}
	free(tofree);
	return (error);
}

#ifdef BHYVE_SNAPSHOT
#define	VTCON_SNAPSHOT_MAGIC		0x314e4f43U	/* "CON1" on disk */
#define	VTCON_SNAPSHOT_VERSION		1U
#define	VTCON_SNAPSHOT_STRING_MAX	(1024U * 1024U)

struct pci_vtcon_port_snapshot {
	uint8_t rx_ready;
	uint8_t announced;
	uint8_t guest_ready;
	uint8_t named;
	uint8_t console_pending;
	uint8_t open_pending;
};

static bool
pci_vtcon_snapshot_port_valid(bool enabled, bool console,
    const struct pci_vtcon_port_snapshot *state)
{

	if (!enabled &&
	    (console || state->rx_ready || state->announced ||
	    state->guest_ready || state->named || state->console_pending ||
	    state->open_pending))
		return (false);
	if (state->guest_ready && !state->announced)
		return (false);
	if (state->named && !state->guest_ready)
		return (false);
	if (state->console_pending &&
	    (!console || !state->guest_ready))
		return (false);
	return (true);
}

static int
pci_vtcon_pause(void *vsc)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_sock *sock;
	int i;

	sc = vsc;
	pthread_mutex_lock(&sc->vsc_mtx);
	for (i = 0; i < VTCON_MAXPORTS; i++) {
		if (!sc->vsc_ports[i].vsp_enabled)
			continue;
		sock = sc->vsc_ports[i].vsp_arg;
		/*
		 * Listener configuration is reconstructible, but a connected host
		 * socket, pending host bytes, or an in-flight event registration
		 * is not portable checkpoint state.
		 */
		if (sock == NULL || sock->vss_open || sock->vss_conn_fd >= 0 ||
		    sock->vss_conn_evp != NULL || sock->vss_write_evp != NULL ||
		    sock->vss_tx_off != 0 || sock->vss_tx_len != 0) {
			pthread_mutex_unlock(&sc->vsc_mtx);
			return (EBUSY);
		}
	}
	return (0);
}

static int
pci_vtcon_resume(void *vsc)
{
	struct pci_vtcon_softc *sc;

	sc = vsc;
	pthread_mutex_unlock(&sc->vsc_mtx);
	return (0);
}

static int
pci_vtcon_snapshot(void *vsc, struct vm_snapshot_meta *meta)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_port *port;
	struct pci_vtcon_port_snapshot ports[VTCON_MAXPORTS];
	struct pci_vtcon_sock *sock;
	uint64_t features;
	uint32_t emerg_wr, magic, max_nr_ports, version;
	uint32_t id, rxq, txq;
	uint16_t cols, rows;
	uint8_t console, enabled, open, ready;
	int error, i;

	sc = vsc;
	magic = VTCON_SNAPSHOT_MAGIC;
	version = VTCON_SNAPSHOT_VERSION;
	features = sc->vsc_features;
	ready = sc->vsc_ready;
	cols = pci_vtcon_decode16(sc, sc->vsc_config->cols);
	rows = pci_vtcon_decode16(sc, sc->vsc_config->rows);
	max_nr_ports = pci_vtcon_decode32(sc, sc->vsc_config->max_nr_ports);
	emerg_wr = pci_vtcon_decode32(sc, sc->vsc_config->emerg_wr);
	/*
	 * The private negotiated-feature cache must agree with the common
	 * VirtIO state before it is committed to an image.  Import already
	 * enforces this relationship; export must not create an image that is
	 * known to be unreconstructible.
	 */
	if (meta->op == VM_SNAPSHOT_SAVE &&
	    features != sc->vsc_vs.vs_negotiated_caps) {
		error = EINVAL;
		goto done;
	}

	SNAPSHOT_LE32_OR_LEAVE(magic, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(version, meta, error, done);
	if (magic != VTCON_SNAPSHOT_MAGIC ||
	    version != VTCON_SNAPSHOT_VERSION) {
		error = ENOTSUP;
		goto done;
	}
	SNAPSHOT_LE64_OR_LEAVE(features, meta, error, done);
	SNAPSHOT_U8_OR_LEAVE(ready, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(cols, meta, error, done);
	SNAPSHOT_LE16_OR_LEAVE(rows, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(max_nr_ports, meta, error, done);
	SNAPSHOT_LE32_OR_LEAVE(emerg_wr, meta, error, done);
	if (ready > 1) {
		error = EINVAL;
		goto done;
	}
	if (vm_snapshot_is_loading(meta) &&
	    (features != sc->vsc_vs.vs_negotiated_caps ||
	    cols != pci_vtcon_decode16(sc, sc->vsc_config->cols) ||
	    rows != pci_vtcon_decode16(sc, sc->vsc_config->rows) ||
	    max_nr_ports !=
	    pci_vtcon_decode32(sc, sc->vsc_config->max_nr_ports))) {
		error = EINVAL;
		goto done;
	}

	for (i = 0; i < VTCON_MAXPORTS; i++) {
		port = &sc->vsc_ports[i];
		sock = port->vsp_arg;
		enabled = port->vsp_enabled;
		console = port->vsp_console;
		open = port->vsp_open;
		id = (uint32_t)port->vsp_id;
		rxq = (uint32_t)port->vsp_rxq;
		txq = (uint32_t)port->vsp_txq;
		ports[i] = (struct pci_vtcon_port_snapshot){
			.rx_ready = port->vsp_rx_ready,
			.announced = port->vsp_announced,
			.guest_ready = port->vsp_guest_ready,
			.named = port->vsp_named,
			.console_pending = port->vsp_console_pending,
			.open_pending = port->vsp_open_pending,
		};
		SNAPSHOT_U8_OR_LEAVE(enabled, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(console, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(open, meta, error, done);
		SNAPSHOT_LE32_OR_LEAVE(id, meta, error, done);
		SNAPSHOT_LE32_OR_LEAVE(rxq, meta, error, done);
		SNAPSHOT_LE32_OR_LEAVE(txq, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(ports[i].rx_ready, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(ports[i].announced, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(ports[i].guest_ready, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(ports[i].named, meta, error, done);
		SNAPSHOT_U8_OR_LEAVE(ports[i].console_pending, meta, error,
		    done);
		SNAPSHOT_U8_OR_LEAVE(ports[i].open_pending, meta, error, done);
		/*
		 * A connected host socket is deliberately not reconstructible state.
		 * pci_vtcon_pause() rejects it before a normal checkpoint, but keep
		 * the on-disk contract self-contained as well: an encoder invoked by
		 * a future snapshot path must not produce an image that restore will
		 * necessarily reject.
		 */
		if (enabled > 1 || console > 1 || open != 0 ||
		    (enabled != 0 && sock == NULL) ||
		    ports[i].rx_ready > 1 || ports[i].announced > 1 ||
		    ports[i].guest_ready > 1 || ports[i].named > 1 ||
		    ports[i].console_pending > 1 ||
		    ports[i].open_pending > 1 ||
		    !pci_vtcon_snapshot_port_valid(enabled, console,
		    &ports[i])) {
			error = EINVAL;
			goto done;
		}
		if (vm_snapshot_is_loading(meta) &&
		    (enabled != port->vsp_enabled ||
		    console != port->vsp_console || open != 0 ||
		    id != (uint32_t)port->vsp_id ||
		    rxq != (uint32_t)port->vsp_rxq ||
		    txq != (uint32_t)port->vsp_txq)) {
			error = EINVAL;
			goto done;
		}
		error = vm_snapshot_identity_string(
		    enabled ? port->vsp_name : NULL,
		    VTCON_SNAPSHOT_STRING_MAX, meta);
		if (error != 0)
			goto done;
		error = vm_snapshot_identity_string(
		    enabled && sock != NULL ? sock->vss_path : NULL,
		    VTCON_SNAPSHOT_STRING_MAX, meta);
		if (error != 0)
			goto done;
	}

	if (meta->op == VM_SNAPSHOT_RESTORE) {
		sc->vsc_features = features;
		sc->vsc_ready = ready;
		sc->vsc_config->emerg_wr = pci_vtcon_encode32(sc, emerg_wr);
		for (i = 0; i < VTCON_MAXPORTS; i++) {
			port = &sc->vsc_ports[i];
			port->vsp_rx_ready = ports[i].rx_ready;
			port->vsp_open = false;
			port->vsp_announced = ports[i].announced;
			port->vsp_guest_ready = ports[i].guest_ready;
			port->vsp_named = ports[i].named;
			port->vsp_console_pending = ports[i].console_pending;
			port->vsp_open_pending = ports[i].open_pending;
		}
	}
	error = 0;

done:
	return (error);
}

/*
 * Restore preflight must not race a listener accept or an already selected
 * socket callback while it compares the destination's immutable port
 * configuration with the incoming image.  Unlike a commit-time checkpoint,
 * this only serializes the local codec: it neither pauses queues nor touches
 * the external listener/backend.
 */
static int
pci_vtcon_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pi;
	struct pci_vtcon_softc *sc;
	bool acquired;
	int error;

	if (meta == NULL || meta->op != VM_SNAPSHOT_VALIDATE ||
	    meta->dev_data == NULL)
		return (EINVAL);
	pi = meta->dev_data;
	sc = pi->pi_arg;
	if (sc == NULL)
		return (EINVAL);

	/*
	 * vm_restore_transaction() has already acquired this non-recursive
	 * mutex through pci_vtcon_pause().  Direct preflight callers do not,
	 * so acquire it only in that case.  Keeping the ownership test here
	 * makes the codec safe in both paths without changing pause ownership.
	 */
	acquired = !pthread_mutex_isowned_np(&sc->vsc_mtx);
	if (acquired)
		pthread_mutex_lock(&sc->vsc_mtx);
	error = vi_pci_snapshot(meta);
	if (acquired)
		pthread_mutex_unlock(&sc->vsc_mtx);
	return (error);
}
#endif

static int
pci_vtcon_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtcon_softc *sc;
	nvlist_t *ports_nvl;
	bool packed;
	int i;

	sc = calloc(1, sizeof(struct pci_vtcon_softc));
	if (sc == NULL)
		return (1);
	sc->vsc_config = calloc(1, sizeof(struct pci_vtcon_config));
	if (sc->vsc_config == NULL) {
		free(sc);
		return (1);
	}
	if (pthread_mutex_init(&sc->vsc_mtx, NULL) != 0)
		goto fail;
	sc->vsc_mtx_initialized = true;

	memcpy(&sc->vsc_consts, &vtcon_vi_consts, sizeof(sc->vsc_consts));
	vi_softc_linkup(&sc->vsc_vs, &sc->vsc_consts, sc, pi,
	    sc->vsc_queues);
	sc->vsc_vs.vs_mtx = &sc->vsc_mtx;

	for (i = 0; i < VTCON_MAXQ; i++) {
		sc->vsc_queues[i].vq_qsize = VTCON_RINGSZ;
		sc->vsc_queues[i].vq_notify = i % 2 == 0
		    ? pci_vtcon_notify_rx
		    : pci_vtcon_notify_tx;
	}
	if (vi_pci_select_transport(&sc->vsc_vs, nvl,
	    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
		goto fail;
	packed = get_config_bool_node_default(nvl, "packed", false);
	if (packed && !vi_pci_is_modern(&sc->vsc_vs)) {
		EPRINTLN("virtio-console packed queues require transport=modern");
		goto fail;
	}
	if (packed)
		sc->vsc_consts.vc_hv_caps |= VIRTIO_F_RING_PACKED;
	sc->vsc_config->max_nr_ports =
	    pci_vtcon_encode32(sc, VTCON_MAXPORTS);
	sc->vsc_config->cols = pci_vtcon_encode16(sc, 80);
	sc->vsc_config->rows = pci_vtcon_encode16(sc, 25);

	/* create control port */
	sc->vsc_control_port.vsp_sc = sc;
	sc->vsc_control_port.vsp_txq = 2;
	sc->vsc_control_port.vsp_rxq = 3;
	sc->vsc_control_port.vsp_cb = pci_vtcon_control_tx;
	sc->vsc_control_port.vsp_enabled = true;

	ports_nvl = find_relative_config_node(nvl, "port");
	if (ports_nvl != NULL) {
		const char *name;
		void *cookie;
		int type;

		cookie = NULL;
		while ((name = nvlist_next(ports_nvl, &type, &cookie)) !=
		    NULL) {
			if (type != NV_TYPE_NVLIST)
				continue;

			if (pci_vtcon_sock_add(sc, name,
			    nvlist_get_nvlist(ports_nvl, name)) < 0) {
				EPRINTLN("cannot create port %s: %s",
				    name, strerror(errno));
				goto fail;
			}
		}
	}

	/* initialize config space */
	if (vi_pci_is_modern(&sc->vsc_vs))
		vi_pci_modern_set_identity(&sc->vsc_vs, VIRTIO_ID_CONSOLE);
	else {
		pci_set_cfgdata16(pi, PCIR_DEVICE,
		    VIRTIO_PCI_TRANSITIONAL_CONSOLE);
		pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
		pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_ID_CONSOLE);
		pci_set_cfgdata16(pi, PCIR_SUBVEND_0, VIRTIO_VENDOR);
	}
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_SIMPLECOMM);

	if (vi_intr_init(&sc->vsc_vs, 1, fbsdrun_virtio_msix()))
		goto fail;
	sc->vsc_intr_initialized = true;
	if (vi_pci_is_modern(&sc->vsc_vs)) {
		if (vi_pci_modern_init(&sc->vsc_vs, 2) != 0)
			goto fail;
	} else
		vi_set_io_bar(&sc->vsc_vs, 0);

	return (0);

fail:
	pci_vtcon_destroy(sc);
	return (1);
}

static const struct pci_devemu pci_de_vcon = {
	.pe_emu =	"virtio-console",
	.pe_init =	pci_vtcon_init,
	.pe_cfgwrite =	vi_pci_modern_cfgwrite,
	.pe_cfgread =	vi_pci_modern_cfgread,
	.pe_barwrite =	vi_pci_write,
	.pe_barread =	vi_pci_read,
	.pe_legacy_config = pci_vtcon_legacy_config,
#ifdef BHYVE_SNAPSHOT
	.pe_snapshot =	vi_pci_snapshot,
	.pe_snapshot_validate = pci_vtcon_snapshot_validate,
	.pe_snapshot_compat = vi_pci_snapshot_compat,
	.pe_pause =	vi_pci_pause,
	.pe_resume =	vi_pci_resume,
#endif
};
PCI_EMUL_SET(pci_de_vcon);
