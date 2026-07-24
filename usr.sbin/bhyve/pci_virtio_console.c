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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <libgen.h>
#include <sysexits.h>

#include "bhyverun.h"
#include "config.h"
#include "debug.h"
#include "iov.h"
#include "pci_emul.h"
#include "virtio.h"
#include "mevent.h"
#include "sockstream.h"

#define	VTCON_RINGSZ	64
#define	VTCON_MAXPORTS	16
#define	VTCON_MAXQ	(VTCON_MAXPORTS * 2 + 2)
#define	VTCON_SOCK_TX_MAX	(1024 * 1024)

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
	struct vqueue_info       vsc_queues[VTCON_MAXQ];
	pthread_mutex_t          vsc_mtx;
	uint64_t                 vsc_cfg;
	uint64_t                 vsc_features;
	char *                   vsc_rootdir;
	int                      vsc_kq;
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
static void pci_vtcon_neg_features(void *, uint64_t);
static void pci_vtcon_sock_accept(int, enum ev_type,  void *);
static void pci_vtcon_sock_rx(int, enum ev_type, void *);
static void pci_vtcon_sock_tx_event(int, enum ev_type, void *);
static void pci_vtcon_sock_tx(struct pci_vtcon_port *, void *, struct iovec *,
    int);
static void pci_vtcon_sock_rx_enable(struct pci_vtcon_port *, void *);
static void pci_vtcon_sock_close(struct pci_vtcon_sock *);
static bool pci_vtcon_control_send(struct pci_vtcon_softc *,
    struct pci_vtcon_control *, const void *, size_t);
static bool pci_vtcon_announce_port(struct pci_vtcon_port *);
static void pci_vtcon_open_port(struct pci_vtcon_port *, bool);
static void pci_vtcon_destroy(struct pci_vtcon_softc *);

static struct virtio_consts vtcon_vi_consts = {
	.vc_name =	"vtcon",
	.vc_nvq =	VTCON_MAXQ,
	.vc_cfgsize =	sizeof(struct pci_vtcon_config),
	.vc_reset =	pci_vtcon_reset,
	.vc_cfgread =	pci_vtcon_cfgread,
	.vc_cfgwrite =	pci_vtcon_cfgwrite,
	.vc_apply_features = pci_vtcon_neg_features,
	.vc_qreset =	pci_vtcon_qreset,
	.vc_hv_caps =	VTCON_S_HOSTCAPS | VIRTIO_F_IN_ORDER |
	    VIRTIO_F_RING_RESET,
};

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
	}
	return (0);
}

static void
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
	void *ptr;

	if (offset < 0 || (size != 1 && size != 2 && size != 4) ||
	    (size_t)offset > sizeof(*sc->vsc_config) ||
	    (size_t)size > sizeof(*sc->vsc_config) - (size_t)offset)
		return (-1);
	ptr = (uint8_t *)sc->vsc_config + offset;
	*retval = 0;
	memcpy(retval, ptr, size);
	return (0);
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
    pci_vtcon_cb_t *cb, pci_vtcon_rx_cb_t *rx_cb, void *arg)
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
pci_vtcon_sock_add(struct pci_vtcon_softc *sc, const char *port_name,
    const nvlist_t *nvl)
{
	struct pci_vtcon_sock *sock = NULL;
	struct sockaddr_un sun;
	const char *name, *path;
	char *cp, *pathcopy;
	long port;
	bool bound = false;
	int s = -1, fd = -1, error = 0;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	port = strtol(port_name, &cp, 0);
	if (*cp != '\0' || port < 0 || port >= VTCON_MAXPORTS) {
		EPRINTLN("vtcon: Invalid port %s", port_name);
		error = -1;
		goto out;
	}

	path = get_config_value_node(nvl, "path");
	if (path == NULL) {
		EPRINTLN("vtcon: required path missing for port %ld", port);
		error = -1;
		goto out;
	}
	name = get_config_value_node(nvl, "name");
	if (name == NULL) {
		EPRINTLN("vtcon: required name missing for port %ld", port);
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
	    pci_vtcon_sock_rx_enable, sock);
	if (sock->vss_port == NULL) {
		error = -1;
		goto out;
	}

out:
	if (error != 0 && bound)
		unlinkat(fd, sun.sun_path, 0);
	if (fd != -1)
		close(fd);

	if (error != 0) {
		if (sock != NULL && sock->vss_server_evp != NULL) {
			mevent_delete_close(sock->vss_server_evp);
			s = -1;
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
		if (sock->vss_write_evp != NULL)
			mevent_delete(sock->vss_write_evp);
		if (sock->vss_conn_evp != NULL)
			mevent_delete_close(sock->vss_conn_evp);
		else if (sock->vss_conn_fd >= 0)
			close(sock->vss_conn_fd);
		if (sock->vss_server_evp != NULL)
			mevent_delete_close(sock->vss_server_evp);
		else if (sock->vss_server_fd >= 0)
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

	s = accept4(sock->vss_server_fd, NULL, NULL, SOCK_NONBLOCK);
	if (s < 0)
		return;

	vs = &sock->vss_sc->vsc_vs;
	VS_LOCK(vs);
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
pci_vtcon_sock_rx(int fd __unused, enum ev_type t __unused, void *arg)
{
	struct pci_vtcon_port *port;
	struct pci_vtcon_sock *sock = (struct pci_vtcon_sock *)arg;
	struct virtio_softc *vs;
	struct vqueue_info *vq;
	struct vi_req req;
	struct iovec iov[VTCON_RINGSZ];
	int len, n;

	vs = &sock->vss_sc->vsc_vs;
	VS_LOCK(vs);
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

	do {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0)
			break;
		if (req.readable != 0 || req.writable != n) {
			WPRINTF(("vtcon: invalid receive descriptor chain"));
			vq_relchain(vq, req.idx, 0);
			continue;
		}
		len = readv(sock->vss_conn_fd, iov, n);

		if (len == 0 || (len < 0 && (errno == EAGAIN ||
		    errno == EWOULDBLOCK))) {
			vq_retchains(vq, 1);
			vq_endchains(vq, 0);
			if (len == 0)
				goto close;

			goto out;
		}
		if (len < 0) {
			vq_retchains(vq, 1);
			goto close;
		}

		vq_relchain(vq, req.idx, len);
		/* Process at most one read per readiness notification. */
		break;
	} while (vq_has_descs(vq));

	vq_endchains(vq, 1);
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
pci_vtcon_sock_tx_event(int fd __unused, enum ev_type type __unused, void *arg)
{
	struct pci_vtcon_sock *sock;
	struct virtio_softc *vs;

	sock = arg;
	vs = &sock->vss_sc->vsc_vs;
	VS_LOCK(vs);
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
		cap = MAX((size_t)4096, sock->vss_tx_cap);
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
	vq_relchain(vq, req.idx, used);
	vq_endchains(vq, 1);
	return (used == msglen);
}


static void
pci_vtcon_notify_tx(void *vsc, struct vqueue_info *vq)
{
	struct pci_vtcon_softc *sc;
	struct pci_vtcon_port *port;
	struct iovec iov[VTCON_RINGSZ];
	struct vi_req req;
	int n;

	sc = vsc;
	if (!pci_vtcon_queue_active(sc, vq->vq_num))
		return;
	port = pci_vtcon_vq_to_port(sc, vq);

	while (vq_has_descs(vq)) {
		n = vq_getchain(vq, iov, nitems(iov), &req);
		if (n <= 0)
			break;
		if (req.writable != 0 || req.readable != n) {
			WPRINTF(("vtcon: invalid transmit descriptor chain"));
			vq_relchain(vq, req.idx, 0);
			continue;
		}
		if (port->vsp_enabled && port->vsp_cb != NULL)
			port->vsp_cb(port, port->vsp_arg, iov, n);

		/*
		 * Release this chain and handle more
		 */
		vq_relchain(vq, req.idx, 0);
	}
	vq_endchains(vq, 1);	/* Generate interrupt if appropriate. */
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
	nvlist_t *ports_nvl;
	int error, port;

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
		error = pci_vtcon_legacy_config_port(ports_nvl, port, opt);
		if (error)
			break;
		port++;
	}
	free(tofree);
	return (error);
}

static int
pci_vtcon_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	struct pci_vtcon_softc *sc;
	nvlist_t *ports_nvl;
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

	vi_softc_linkup(&sc->vsc_vs, &vtcon_vi_consts, sc, pi, sc->vsc_queues);
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
};
PCI_EMUL_SET(pci_de_vcon);
