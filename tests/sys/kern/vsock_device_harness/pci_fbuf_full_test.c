/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * TU-include coverage harness for bhyve's framebuffer PCI device
 * (usr.sbin/bhyve/pci_fbuf.c).  The device source is compiled directly into
 * the test so its static entry points can be driven without a running VM.
 * The bhyve infrastructure it depends on (pci_emul, vmmapi, console, rfb,
 * vga, config nvlist, snapshot codec) is replaced with independent mocks
 * defined below; assertions are checked against the documented BAR/config
 * layout and the documented "-s fbuf" option semantics rather than the
 * implementation's own output.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

/*
 * ---- Neutralize the kernel / vmmapi header maze -----------------------------
 * pci_fbuf.c pulls in <dev/vmm/vmm_mem.h>, <machine/vmm.h> and <vmmapi.h>.
 * Pre-defining their include guards turns those includes into no-ops so the
 * device sees the minimal, self-contained declarations provided here instead.
 * <machine/vmm_snapshot.h> is deliberately left real: it supplies the snapshot
 * metadata types and the SNAPSHOT_*_OR_LEAVE macros the codec uses.
 */
#define	_DEV_VMM_MEM_H_
#define	_VMM_H_
#define	_VMMAPI_H_

enum { VM_FRAMEBUFFER = 2 };

typedef uint64_t vm_paddr_t;
struct vmctx;

void *vm_create_devmem(struct vmctx *, int, const char *, size_t);
int vm_mmap_memseg(struct vmctx *, vm_paddr_t, int, vm_paddr_t, size_t, int);
int vm_munmap_memseg(struct vmctx *, vm_paddr_t, size_t);

/*
 * Pull in the harness mock headers, then define the *real* bhyve include
 * guards so that when pci_fbuf.c later quote-includes these by name it sees
 * the mocks already in place instead of the real infrastructure headers.
 * bhyvegc.h/console.h/rfb.h/amd64/vga.h are left real: they are pure
 * prototype headers whose interfaces the mocks implement, and including them
 * here keeps the mock definitions -Werror clean.
 */
#include "config.h"		/* nvlist_t + get_config_* declarations */
#define	__CONFIG_H__		/* block real usr.sbin/bhyve/config.h */
#include "debug.h"		/* EPRINTLN / PRINTLN */
#define	_DEBUG_H_		/* block real usr.sbin/bhyve/debug.h */
#include "bhyverun.h"
#define	_BHYVERUN_H_		/* block real usr.sbin/bhyve/bhyverun.h */
#include "bhyvegc.h"
#include "console.h"
#ifdef __amd64__
#include "amd64/vga.h"
#endif
#include "rfb.h"
#include <machine/vmm_snapshot.h>
#include "snapshot.h"
#define	_BHYVE_SNAPSHOT_	/* block real usr.sbin/bhyve/snapshot.h */

/*
 * ---- pci_emul mock ----------------------------------------------------------
 * The harness ships a mock pci_emul.h, but it declares pci_emul_add_msicap as
 * void (pci_fbuf.c assigns its int result) and lacks the .pe_baraddr member,
 * so define the guard and provide a device-accurate subset here.
 */
#define	MOCK_PCI_EMUL_H		/* block harness mock pci_emul.h */
#define	_PCI_EMUL_H_		/* block real usr.sbin/bhyve/pci_emul.h */

enum pcibar_type {
	PCIBAR_NONE,
	PCIBAR_IO,
	PCIBAR_MEM32,
	PCIBAR_MEM64,
};
struct pcibar {
	enum pcibar_type type;
	uint64_t size;
	uint64_t addr;
};
struct pci_devinst {
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
	void (*pe_baraddr)(struct pci_devinst *, int, int, uint64_t);
	int (*pe_snapshot)(struct vm_snapshot_meta *);
	int (*pe_snapshot_validate)(struct vm_snapshot_meta *);
	uint32_t pe_migration_flags;
};
#define	PCI_EMUL_SET(x)

#define	PCI_MIGRATION_F_STATE_CODEC	(1U << 0)
#define	PCI_MIGRATION_F_COMPAT_FIXED	(1U << 1)
#define	PCI_MIGRATION_F_DMA_NONE		(1U << 3)
#define	PCI_MIGRATION_F_QUIESCE_NONE	(1U << 5)

#define	PCIR_DEVICE		0x02
#define	PCIR_VENDOR		0x00
#define	PCIR_CLASS		0x0b
#define	PCIR_SUBCLASS		0x0a
#define	PCIC_DISPLAY		0x03
#define	PCIS_DISPLAY_VGA	0x00

void pci_set_cfgdata8(struct pci_devinst *, int, uint8_t);
void pci_set_cfgdata16(struct pci_devinst *, int, uint16_t);
int pci_emul_alloc_bar(struct pci_devinst *, int, enum pcibar_type, uint64_t);
int pci_emul_add_msicap(struct pci_devinst *, int);

/* ---- mock control state ---------------------------------------------------- */
static bool g_devmem_fail;
static int g_mmap_ret;
static int g_munmap_ret;
static unsigned g_mmap_calls;
static unsigned g_munmap_calls;
static uint64_t g_last_mmap_addr;
static bool g_alloc_bar_fail;

static struct bhyvegc_image g_console_image;
static int g_fb_register_ret;
static unsigned g_fb_register_calls;
static unsigned g_fb_unregister_calls;
static unsigned g_console_init_calls;
static int g_resize_w, g_resize_h;
static unsigned g_resize_calls;

static bool g_vga_init_null;
static unsigned g_vga_render_calls;
static int g_vga_token;

static int g_rfb_ret;
static unsigned g_rfb_calls;
static sa_family_t g_rfb_family;
static char g_rfb_host[256];
static int g_rfb_port;

/* ---- vmmapi mock ----------------------------------------------------------- */
void *
vm_create_devmem(struct vmctx *ctx __unused, int segid __unused,
    const char *name __unused, size_t len)
{

	if (g_devmem_fail)
		return (MAP_FAILED);
	return (calloc(1, len));
}

int
vm_mmap_memseg(struct vmctx *ctx __unused, vm_paddr_t gpa, int segid __unused,
    vm_paddr_t segoff __unused, size_t len __unused, int prot __unused)
{

	g_mmap_calls++;
	g_last_mmap_addr = gpa;
	return (g_mmap_ret);
}

int
vm_munmap_memseg(struct vmctx *ctx __unused, vm_paddr_t gpa __unused,
    size_t len __unused)
{

	g_munmap_calls++;
	return (g_munmap_ret);
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

int
pci_emul_add_msicap(struct pci_devinst *pi __unused, int msgnum __unused)
{

	return (0);
}

/* ---- console mock ---------------------------------------------------------- */
void
console_init(int w __unused, int h __unused, void *fbaddr __unused)
{

	g_console_init_calls++;
}

struct bhyvegc_image *
console_get_image(void)
{

	return (&g_console_image);
}

int
console_fb_register(const char *owner __unused, fb_render_func_t render_cb __unused,
    void *arg __unused)
{

	g_fb_register_calls++;
	return (g_fb_register_ret);
}

int
console_fb_unregister(const char *owner __unused, void *arg __unused)
{

	g_fb_unregister_calls++;
	return (0);
}

void
bhyvegc_resize(struct bhyvegc *gc __unused, int width, int height)
{

	g_resize_calls++;
	g_resize_w = width;
	g_resize_h = height;
}

/* ---- vga mock -------------------------------------------------------------- */
void *
vga_init(int io_only __unused)
{

	if (g_vga_init_null)
		return (NULL);
	return (&g_vga_token);
}

void
vga_render(struct bhyvegc *gc __unused, void *arg __unused)
{

	g_vga_render_calls++;
}

/* ---- rfb mock -------------------------------------------------------------- */
int
rfb_init(sa_family_t family, const char *hostname, int port, int wait __unused,
    const char *password __unused)
{

	g_rfb_calls++;
	g_rfb_family = family;
	g_rfb_port = port;
	if (hostname != NULL)
		strlcpy(g_rfb_host, hostname, sizeof(g_rfb_host));
	else
		g_rfb_host[0] = '\0';
	return (g_rfb_ret);
}

/* ---- config nvlist mock ---------------------------------------------------- */
struct cfg_ent {
	const char *key;
	const char *val;
};
static struct cfg_ent g_cfg[32];
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

bool
get_config_bool_node_default(const nvlist_t *nvl __unused, const char *name,
    bool def)
{
	const char *v;

	v = get_config_value_node(nvl, name);
	if (v == NULL)
		return (def);
	return (strcmp(v, "true") == 0 || strcmp(v, "1") == 0);
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

int
vm_snapshot_le32(uint32_t *value, struct vm_snapshot_meta *meta)
{
	uint8_t bytes[sizeof(*value)];
	int error;

	if (meta->op == VM_SNAPSHOT_SAVE)
		le32enc(bytes, *value);
	error = vm_snapshot_buf(bytes, sizeof(bytes), meta);
	if (error == 0 && meta->op != VM_SNAPSHOT_SAVE)
		*value = le32dec(bytes);
	return (error);
}

/* ---- Device under test ----------------------------------------------------- */
#include "pci_fbuf.c"

/* Documented BAR / geometry constants used as independent oracles. */
#define	ORACLE_FB_SIZE		(32U * 1024U * 1024U)
#define	ORACLE_DMEMSZ		PCI_FBUF_REG_SIZE
#define	ORACLE_COLS_DEFAULT	1024
#define	ORACLE_ROWS_DEFAULT	768

static void
controls_reset(void)
{

	g_devmem_fail = false;
	g_mmap_ret = 0;
	g_munmap_ret = 0;
	g_mmap_calls = 0;
	g_munmap_calls = 0;
	g_last_mmap_addr = 0;
	g_alloc_bar_fail = false;
	g_fb_register_ret = 0;
	g_fb_register_calls = 0;
	g_fb_unregister_calls = 0;
	g_console_init_calls = 0;
	g_resize_calls = 0;
	g_vga_init_null = false;
	g_vga_render_calls = 0;
	g_rfb_ret = 0;
	g_rfb_calls = 0;
	memset(&g_console_image, 0, sizeof(g_console_image));
	fbuf_sc = NULL;
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

/* Build a softc with valid default geometry for direct entry-point calls. */
static struct pci_fbuf_softc *
make_sc(void)
{
	struct pci_fbuf_softc *sc;

	sc = calloc(1, sizeof(*sc));
	ATF_REQUIRE(sc != NULL);
	sc->gc_image = &g_console_image;
	pci_fbuf_set_u16(sc, PCI_FBUF_REG_WIDTH, ORACLE_COLS_DEFAULT);
	pci_fbuf_set_u16(sc, PCI_FBUF_REG_HEIGHT, ORACLE_ROWS_DEFAULT);
	return (sc);
}

#ifdef BHYVE_SNAPSHOT
/*
 * struct vm_snapshot_meta has const buffer members, so it can only be
 * initialized, never assigned.  Build each one fresh via copy-initialization.
 */
static struct vm_snapshot_meta
make_meta(void *dev, enum vm_snapshot_op op, uint8_t *buf, size_t rem)
{
	struct vm_snapshot_meta m = {
		.dev_data = dev,
		.op = op,
		.buffer = { .buf = buf, .buf_rem = rem,
		    .buf_start = buf, .buf_size = rem },
	};

	return (m);
}
#endif

/* -------------------------------------------------------------------------- */

ATF_TC_WITHOUT_HEAD(init_success_defaults);
ATF_TC_BODY(init_success_defaults, tc)
{
	struct pci_devinst *pi;
	struct pci_fbuf_softc *sc;
	uint64_t v;

	controls_reset();
	pi = make_pi();

	ATF_REQUIRE_EQ(0, pci_fbuf_init(pi, NULL));
	sc = pi->pi_arg;
	ATF_REQUIRE(sc != NULL);

	/* Config space matches the documented Nahanni framebuffer identity. */
	ATF_CHECK_EQ(0x40FB, le16dec(&pi->pi_cfgdata[PCIR_DEVICE]));
	ATF_CHECK_EQ(0xFB5D, le16dec(&pi->pi_cfgdata[PCIR_VENDOR]));
	ATF_CHECK_EQ(PCIC_DISPLAY, pi->pi_cfgdata[PCIR_CLASS]);
	ATF_CHECK_EQ(PCIS_DISPLAY_VGA, pi->pi_cfgdata[PCIR_SUBCLASS]);

	/* BAR0 is the register window; BAR1 is the framebuffer. */
	ATF_CHECK_EQ(PCIBAR_MEM32, pi->pi_bar[0].type);
	ATF_CHECK_EQ((uint64_t)ORACLE_DMEMSZ, pi->pi_bar[0].size);
	ATF_CHECK_EQ(PCIBAR_MEM32, pi->pi_bar[1].type);
	ATF_CHECK_EQ((uint64_t)ORACLE_FB_SIZE, pi->pi_bar[1].size);

	/* Register defaults. */
	ATF_REQUIRE(pci_fbuf_register_read(sc->memregs, PCI_FBUF_REG_FBSIZE, 4,
	    &v));
	ATF_CHECK_EQ((uint64_t)ORACLE_FB_SIZE, v);
	ATF_CHECK_EQ(ORACLE_COLS_DEFAULT,
	    pci_fbuf_get_u16(sc, PCI_FBUF_REG_WIDTH));
	ATF_CHECK_EQ(ORACLE_ROWS_DEFAULT,
	    pci_fbuf_get_u16(sc, PCI_FBUF_REG_HEIGHT));
	ATF_CHECK_EQ(32, pci_fbuf_get_u16(sc, PCI_FBUF_REG_DEPTH));

	/* Default source is internal, so a renderer is registered exactly once. */
	ATF_CHECK_EQ(1, g_fb_register_calls);
	ATF_CHECK_EQ(1, g_console_init_calls);
	ATF_CHECK_EQ(1, g_rfb_calls);
	ATF_CHECK(fbuf_sc == sc);

	/* A second device is refused. */
	ATF_CHECK_EQ(-1, pci_fbuf_init(make_pi(), NULL));
}

ATF_TC_WITHOUT_HEAD(init_failure_paths);
ATF_TC_BODY(init_failure_paths, tc)
{
	struct pci_devinst *pi;

	/* vm_create_devmem failure. */
	controls_reset();
	g_devmem_fail = true;
	pi = make_pi();
	ATF_CHECK_EQ(-1, pci_fbuf_init(pi, NULL));
	ATF_CHECK(pi->pi_arg == NULL);
	ATF_CHECK(fbuf_sc == NULL);

	/* parse_config rejects a bad vga token. */
	controls_reset();
	cfg_set("vga", "bogus");
	ATF_CHECK_EQ(-1, pci_fbuf_init(make_pi(), NULL));

	/* vga=on requests full VGA rendering, which is not enabled. */
	controls_reset();
	cfg_set("vga", "on");
	ATF_CHECK_EQ(-1, pci_fbuf_init(make_pi(), NULL));

	/* Renderer ownership conflict unwinds. */
	controls_reset();
	g_fb_register_ret = -1;
	ATF_CHECK_EQ(-1, pci_fbuf_init(make_pi(), NULL));

	/* vga_init failure. */
	controls_reset();
	g_vga_init_null = true;
	ATF_CHECK_EQ(ENXIO, pci_fbuf_init(make_pi(), NULL));
	ATF_CHECK_EQ(1, g_fb_unregister_calls);

	/* rfb_init failure unwinds after the renderer was registered. */
	controls_reset();
	g_rfb_ret = -1;
	ATF_CHECK_EQ(-1, pci_fbuf_init(make_pi(), NULL));
	ATF_CHECK_EQ(1, g_fb_unregister_calls);
	ATF_CHECK(fbuf_sc == NULL);
}

ATF_TC_WITHOUT_HEAD(init_external_source);
ATF_TC_BODY(init_external_source, tc)
{
	struct pci_devinst *pi;
	struct pci_fbuf_softc *sc;

	/* source=external requires vga=off and suppresses renderer ownership. */
	controls_reset();
	cfg_set("vga", "off");
	cfg_set("source", "external");
	pi = make_pi();
	ATF_REQUIRE_EQ(0, pci_fbuf_init(pi, NULL));
	sc = pi->pi_arg;
	ATF_CHECK_EQ(1, sc->external_source);
	ATF_CHECK_EQ(0, g_fb_register_calls);
	ATF_CHECK_EQ(0, sc->vga_enabled);
	ATF_CHECK_EQ(1, g_rfb_calls);
}

ATF_TC_WITHOUT_HEAD(parse_rfb_ipv4_and_port);
ATF_TC_BODY(parse_rfb_ipv4_and_port, tc)
{
	struct pci_fbuf_softc *sc;

	/* host:port */
	controls_reset();
	sc = make_sc();
	cfg_set("tcp", "192.0.2.10:5901");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(AF_UNSPEC, sc->rfb_family);
	ATF_CHECK_STREQ("192.0.2.10", sc->rfb_host);
	ATF_CHECK_EQ(5901, sc->rfb_port);

	/* port only */
	controls_reset();
	sc = make_sc();
	cfg_set("tcp", "5902");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK(sc->rfb_host == NULL);
	ATF_CHECK_EQ(5902, sc->rfb_port);

	/* host with an empty port is rejected. */
	controls_reset();
	sc = make_sc();
	cfg_set("tcp", "host:");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* "rfb" is preferred over "tcp". */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "10.0.0.1:1");
	cfg_set("tcp", "10.0.0.2:2");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_STREQ("10.0.0.1", sc->rfb_host);
	ATF_CHECK_EQ(1, sc->rfb_port);
}

ATF_TC_WITHOUT_HEAD(parse_rfb_ipv6);
ATF_TC_BODY(parse_rfb_ipv6, tc)
{
	struct pci_fbuf_softc *sc;

	/* [addr]:port */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "[2001:db8::1]:5903");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(AF_INET6, sc->rfb_family);
	ATF_CHECK_STREQ("2001:db8::1", sc->rfb_host);
	ATF_CHECK_EQ(5903, sc->rfb_port);

	/* [addr] with no port is accepted (port defaults to 0). */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "[2001:db8::2]");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(AF_INET6, sc->rfb_family);
	ATF_CHECK_STREQ("2001:db8::2", sc->rfb_host);
	ATF_CHECK_EQ(0, sc->rfb_port);

	/* Missing closing bracket. */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "[2001:db8::3");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* Empty brackets. */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "[]");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* Trailing junk after the bracket. */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "[2001:db8::4]x");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* Colon present but empty port. */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "[2001:db8::5]:");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));
}

ATF_TC_WITHOUT_HEAD(parse_rfb_unix);
ATF_TC_BODY(parse_rfb_unix, tc)
{
	struct pci_fbuf_softc *sc;
	char toolong[16 + SUNPATHLEN + 8];

	/* Valid UNIX path. */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "unix:/tmp/fbuf.sock");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(AF_UNIX, sc->rfb_family);
	ATF_CHECK_STREQ("/tmp/fbuf.sock", sc->rfb_host);

	/* Empty UNIX path. */
	controls_reset();
	sc = make_sc();
	cfg_set("rfb", "unix:");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* Over-long UNIX path. */
	controls_reset();
	sc = make_sc();
	strcpy(toolong, "unix:");
	memset(toolong + 5, 'a', SUNPATHLEN + 2);
	toolong[5 + SUNPATHLEN + 2] = '\0';
	cfg_set("rfb", toolong);
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));
}

ATF_TC_WITHOUT_HEAD(parse_vga_source_and_geometry);
ATF_TC_BODY(parse_vga_source_and_geometry, tc)
{
	struct pci_fbuf_softc *sc;

	/* vga=off */
	controls_reset();
	sc = make_sc();
	cfg_set("vga", "off");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(0, sc->vga_enabled);

	/* vga=io */
	controls_reset();
	sc = make_sc();
	cfg_set("vga", "io");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(1, sc->vga_enabled);
	ATF_CHECK_EQ(0, sc->vga_full);

	/* vga=on */
	controls_reset();
	sc = make_sc();
	cfg_set("vga", "on");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(1, sc->vga_enabled);
	ATF_CHECK_EQ(1, sc->vga_full);

	/* source=fbuf / external */
	controls_reset();
	sc = make_sc();
	cfg_set("source", "fbuf");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(0, sc->external_source);

	controls_reset();
	sc = make_sc();
	cfg_set("vga", "off");
	cfg_set("source", "external");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(1, sc->external_source);

	/* Bad source token. */
	controls_reset();
	sc = make_sc();
	cfg_set("source", "nope");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* external + vga enabled is a contradiction. */
	controls_reset();
	sc = make_sc();
	cfg_set("source", "external");
	cfg_set("vga", "io");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* Custom width/height. */
	controls_reset();
	sc = make_sc();
	cfg_set("w", "1920");
	cfg_set("h", "1080");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(1920, pci_fbuf_get_u16(sc, PCI_FBUF_REG_WIDTH));
	ATF_CHECK_EQ(1080, pci_fbuf_get_u16(sc, PCI_FBUF_REG_HEIGHT));

	/* Above the documented maximum. */
	controls_reset();
	sc = make_sc();
	cfg_set("w", "3841");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* Below the documented minimum. */
	controls_reset();
	sc = make_sc();
	cfg_set("w", "320");
	ATF_CHECK_EQ(-1, pci_fbuf_parse_config(sc, NULL));

	/* wait + password are honored. */
	controls_reset();
	sc = make_sc();
	cfg_set("wait", "true");
	cfg_set("password", "secret");
	ATF_REQUIRE_EQ(0, pci_fbuf_parse_config(sc, NULL));
	ATF_CHECK_EQ(1, sc->rfb_wait);
	ATF_REQUIRE(sc->rfb_password != NULL);
	ATF_CHECK_STREQ("secret", sc->rfb_password);
}

ATF_TC_WITHOUT_HEAD(bar_read_write);
ATF_TC_BODY(bar_read_write, tc)
{
	struct pci_devinst *pi;
	struct pci_fbuf_softc *sc;

	controls_reset();
	pi = make_pi();
	sc = make_sc();
	pi->pi_arg = sc;

	/* A normal register write is observable through a read. */
	pci_fbuf_write(pi, 0, PCI_FBUF_REG_DEPTH, 2, 24);
	ATF_CHECK_EQ(24, pci_fbuf_read(pi, 0, PCI_FBUF_REG_DEPTH, 2));

	/* An out-of-window access is rejected without disturbing state. */
	pci_fbuf_write(pi, 0, PCI_FBUF_REG_SIZE - 1, 4, 0xdeadbeef);
	ATF_CHECK_EQ(0, pci_fbuf_read(pi, 0, PCI_FBUF_REG_SIZE - 1, 4));

	/* A 16-bit read that would run off the register window yields 0. */
	ATF_CHECK_EQ(0, pci_fbuf_get_u16(sc, PCI_FBUF_REG_SIZE));
}

ATF_TC_WITHOUT_HEAD(update_mode_transitions);
ATF_TC_BODY(update_mode_transitions, tc)
{
	struct pci_devinst *pi;
	struct pci_fbuf_softc *sc;

	controls_reset();
	pi = make_pi();
	sc = calloc(1, sizeof(*sc));
	ATF_REQUIRE(sc != NULL);
	sc->gc_image = &g_console_image;
	pi->pi_arg = sc;

	/* 0x0 geometry from VESA mode switches into VGA mode. */
	g_console_image.vgamode = 0;
	pci_fbuf_set_u16(sc, PCI_FBUF_REG_WIDTH, 0);
	pci_fbuf_write(pi, 0, PCI_FBUF_REG_HEIGHT, 2, 0);
	ATF_CHECK_EQ(1, g_console_image.vgamode);
	ATF_CHECK_EQ(0, sc->gc_width);
	ATF_CHECK_EQ(0, sc->gc_height);

	/* A nonzero geometry from VGA mode switches back into VESA mode. */
	pci_fbuf_set_u16(sc, PCI_FBUF_REG_WIDTH, 800);
	pci_fbuf_write(pi, 0, PCI_FBUF_REG_HEIGHT, 2, 600);
	ATF_CHECK_EQ(0, g_console_image.vgamode);
}

ATF_TC_WITHOUT_HEAD(baraddr_map_unmap);
ATF_TC_BODY(baraddr_map_unmap, tc)
{
	struct pci_devinst *pi;
	struct pci_fbuf_softc *sc;

	controls_reset();
	pi = make_pi();
	sc = make_sc();
	pi->pi_arg = sc;

	/* Only BAR1 (the framebuffer) participates. */
	pci_fbuf_baraddr(pi, 0, 1, 0x1000);
	ATF_CHECK_EQ(0, g_mmap_calls);

	/* Enable maps the framebuffer segment and records the address. */
	pci_fbuf_baraddr(pi, 1, 1, 0xC0000000);
	ATF_CHECK_EQ(1, g_mmap_calls);
	ATF_CHECK_EQ((uint32_t)0xC0000000, sc->fbaddr);

	/* Disable unmaps and clears the address. */
	pci_fbuf_baraddr(pi, 1, 0, 0);
	ATF_CHECK_EQ(1, g_munmap_calls);
	ATF_CHECK_EQ(0, sc->fbaddr);

	/* A failed mapping leaves the recorded address untouched. */
	sc->fbaddr = 0;
	g_mmap_ret = -1;
	pci_fbuf_baraddr(pi, 1, 1, 0xD0000000);
	ATF_CHECK_EQ(0, sc->fbaddr);

	/* A failed unmap is reported but still clears the address. */
	sc->fbaddr = 0xE0000000;
	g_munmap_ret = -1;
	pci_fbuf_baraddr(pi, 1, 0, 0);
	ATF_CHECK_EQ(0, sc->fbaddr);
}

ATF_TC_WITHOUT_HEAD(render_paths);
ATF_TC_BODY(render_paths, tc)
{
	struct pci_fbuf_softc *sc;

	controls_reset();
	sc = make_sc();

	/* Full VGA + VGA mode delegates to the VGA renderer. */
	sc->vga_full = 1;
	g_console_image.vgamode = 1;
	pci_fbuf_render(NULL, sc);
	ATF_CHECK_EQ(1, g_vga_render_calls);

	/* Full VGA but VESA mode falls through to the framebuffer path. */
	g_console_image.vgamode = 0;
	sc->gc_width = 0;
	sc->gc_height = 0;
	pci_fbuf_render(NULL, sc);
	ATF_CHECK_EQ(1, g_vga_render_calls);	/* not incremented */
	ATF_CHECK_EQ(1, g_resize_calls);
	ATF_CHECK_EQ(ORACLE_COLS_DEFAULT, g_resize_w);
	ATF_CHECK_EQ(ORACLE_ROWS_DEFAULT, g_resize_h);

	/* A second render at the same geometry does not resize again. */
	pci_fbuf_render(NULL, sc);
	ATF_CHECK_EQ(1, g_resize_calls);

	/* Out-of-range geometry is refused rather than resized. */
	sc->vga_full = 0;
	pci_fbuf_set_u16(sc, PCI_FBUF_REG_WIDTH, 100);
	pci_fbuf_render(NULL, sc);
	ATF_CHECK_EQ(1, g_resize_calls);	/* unchanged */
}

#ifdef BHYVE_SNAPSHOT
ATF_TC_WITHOUT_HEAD(snapshot_save_restore);
ATF_TC_BODY(snapshot_save_restore, tc)
{
	struct pci_devinst pi_save, pi_restore;
	struct pci_fbuf_softc sc_save, sc_restore;
	struct bhyvegc_image image_save, image_restore;
	uint8_t *buf;
	size_t bufsz, used;

	controls_reset();
	bufsz = 4 + PCI_FBUF_REG_SIZE + FB_SIZE + 64;
	buf = malloc(bufsz);
	ATF_REQUIRE(buf != NULL);

	memset(&sc_save, 0, sizeof(sc_save));
	memset(&sc_restore, 0, sizeof(sc_restore));
	memset(&image_save, 0, sizeof(image_save));
	memset(&image_restore, 0, sizeof(image_restore));
	sc_save.gc_image = &image_save;
	sc_restore.gc_image = &image_restore;
	sc_save.fb_base = calloc(1, FB_SIZE);
	sc_restore.fb_base = calloc(1, FB_SIZE);
	ATF_REQUIRE(sc_save.fb_base != NULL && sc_restore.fb_base != NULL);
	pi_save.pi_arg = &sc_save;
	pi_restore.pi_arg = &sc_restore;

	/* Seed distinctive register state and one framebuffer pixel. */
	pci_fbuf_set_u16(&sc_save, PCI_FBUF_REG_WIDTH, 1280);
	pci_fbuf_set_u16(&sc_save, PCI_FBUF_REG_HEIGHT, 1024);
	sc_save.fb_base[7] = 0x5a;

	/* Save. */
	{
		struct vm_snapshot_meta meta = make_meta(&pi_save,
		    VM_SNAPSHOT_SAVE, buf, bufsz);

		ATF_REQUIRE_EQ(0, pci_fbuf_snapshot(&meta));
		used = bufsz - meta.buffer.buf_rem;
	}
	ATF_CHECK(used == 4 + PCI_FBUF_REG_SIZE + FB_SIZE);

	/* Restore into the second instance. */
	{
		struct vm_snapshot_meta meta = make_meta(&pi_restore,
		    VM_SNAPSHOT_RESTORE, buf, used);

		ATF_REQUIRE_EQ(0, pci_fbuf_snapshot(&meta));
	}
	ATF_CHECK_EQ(1280, pci_fbuf_get_u16(&sc_restore, PCI_FBUF_REG_WIDTH));
	ATF_CHECK_EQ(1024, pci_fbuf_get_u16(&sc_restore, PCI_FBUF_REG_HEIGHT));
	ATF_CHECK_EQ(0x5a, sc_restore.fb_base[7]);

	/* Restore with a corrupted magic is rejected. */
	buf[0] ^= 0xff;
	{
		struct vm_snapshot_meta meta = make_meta(&pi_restore,
		    VM_SNAPSHOT_RESTORE, buf, used);

		ATF_CHECK_EQ(EINVAL, pci_fbuf_snapshot(&meta));
	}
	buf[0] ^= 0xff;

	/* A short buffer surfaces the codec error through the goto. */
	{
		struct vm_snapshot_meta meta = make_meta(&pi_save,
		    VM_SNAPSHOT_SAVE, buf, 2);

		ATF_CHECK(pci_fbuf_snapshot(&meta) != 0);
	}

	free(buf);
}

ATF_TC_WITHOUT_HEAD(snapshot_argument_guards);
ATF_TC_BODY(snapshot_argument_guards, tc)
{
	struct pci_devinst pi;
	uint8_t buf[8];

	controls_reset();

	/* NULL meta. */
	ATF_CHECK_EQ(EINVAL, pci_fbuf_snapshot(NULL));

	/* NULL dev_data. */
	{
		struct vm_snapshot_meta meta = make_meta(NULL,
		    VM_SNAPSHOT_SAVE, buf, sizeof(buf));

		ATF_CHECK_EQ(EINVAL, pci_fbuf_snapshot(&meta));
	}

	/* dev_data present but the device has no softc yet. */
	pi.pi_arg = NULL;
	{
		struct vm_snapshot_meta meta = make_meta(&pi,
		    VM_SNAPSHOT_SAVE, buf, sizeof(buf));

		ATF_CHECK_EQ(EINVAL, pci_fbuf_snapshot(&meta));
	}
}

ATF_TC_WITHOUT_HEAD(snapshot_validate);
ATF_TC_BODY(snapshot_validate, tc)
{
	struct pci_devinst pi;
	struct pci_fbuf_softc sc;
	struct bhyvegc_image image;
	uint8_t *buf;
	size_t bufsz, used;

	controls_reset();
	bufsz = 4 + PCI_FBUF_REG_SIZE + FB_SIZE + 64;
	buf = malloc(bufsz);
	ATF_REQUIRE(buf != NULL);

	memset(&sc, 0, sizeof(sc));
	memset(&image, 0, sizeof(image));
	sc.gc_image = &image;
	sc.fb_base = calloc(1, FB_SIZE);
	ATF_REQUIRE(sc.fb_base != NULL);
	pi.pi_arg = &sc;
	pci_fbuf_set_u16(&sc, PCI_FBUF_REG_WIDTH, 1024);
	pci_fbuf_set_u16(&sc, PCI_FBUF_REG_HEIGHT, 768);

	/* Produce a valid image to validate against. */
	{
		struct vm_snapshot_meta meta = make_meta(&pi,
		    VM_SNAPSHOT_SAVE, buf, bufsz);

		ATF_REQUIRE_EQ(0, pci_fbuf_snapshot(&meta));
		used = bufsz - meta.buffer.buf_rem;
	}

	/* A well-formed image validates cleanly and consumes it whole. */
	{
		struct vm_snapshot_meta meta = make_meta(NULL,
		    VM_SNAPSHOT_VALIDATE, buf, used);

		ATF_CHECK_EQ(0, pci_fbuf_snapshot_validate(&meta));
	}

	/* NULL meta / wrong op. */
	ATF_CHECK_EQ(EINVAL, pci_fbuf_snapshot_validate(NULL));
	{
		struct vm_snapshot_meta meta = make_meta(NULL,
		    VM_SNAPSHOT_SAVE, buf, used);

		ATF_CHECK_EQ(EINVAL, pci_fbuf_snapshot_validate(&meta));
	}

	/* Wrong magic. */
	buf[0] ^= 0xff;
	{
		struct vm_snapshot_meta meta = make_meta(NULL,
		    VM_SNAPSHOT_VALIDATE, buf, used);

		ATF_CHECK_EQ(EINVAL, pci_fbuf_snapshot_validate(&meta));
	}
	buf[0] ^= 0xff;

	/* Truncated before the magic. */
	{
		struct vm_snapshot_meta meta = make_meta(NULL,
		    VM_SNAPSHOT_VALIDATE, buf, 2);

		ATF_CHECK(pci_fbuf_snapshot_validate(&meta) != 0);
	}

	/* Truncated after the magic but before the registers. */
	{
		struct vm_snapshot_meta meta = make_meta(NULL,
		    VM_SNAPSHOT_VALIDATE, buf, 6);

		ATF_CHECK(pci_fbuf_snapshot_validate(&meta) != 0);
	}

	/* Truncated inside the framebuffer streaming loop. */
	{
		struct vm_snapshot_meta meta = make_meta(NULL,
		    VM_SNAPSHOT_VALIDATE, buf, 4 + PCI_FBUF_REG_SIZE + 16);

		ATF_CHECK(pci_fbuf_snapshot_validate(&meta) != 0);
	}

	free(buf);
}
#endif /* BHYVE_SNAPSHOT */

ATF_TC_WITHOUT_HEAD(devemu_registration);
ATF_TC_BODY(devemu_registration, tc)
{

	ATF_CHECK_STREQ("fbuf", pci_fbuf.pe_emu);
	ATF_CHECK(pci_fbuf.pe_init == pci_fbuf_init);
	ATF_CHECK(pci_fbuf.pe_barwrite == pci_fbuf_write);
	ATF_CHECK(pci_fbuf.pe_barread == pci_fbuf_read);
	ATF_CHECK(pci_fbuf.pe_baraddr == pci_fbuf_baraddr);
#ifdef BHYVE_SNAPSHOT
	ATF_CHECK(pci_fbuf.pe_snapshot == pci_fbuf_snapshot);
	ATF_CHECK(pci_fbuf.pe_snapshot_validate == pci_fbuf_snapshot_validate);
#endif
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, init_success_defaults);
	ATF_TP_ADD_TC(tp, init_failure_paths);
	ATF_TP_ADD_TC(tp, init_external_source);
	ATF_TP_ADD_TC(tp, parse_rfb_ipv4_and_port);
	ATF_TP_ADD_TC(tp, parse_rfb_ipv6);
	ATF_TP_ADD_TC(tp, parse_rfb_unix);
	ATF_TP_ADD_TC(tp, parse_vga_source_and_geometry);
	ATF_TP_ADD_TC(tp, bar_read_write);
	ATF_TP_ADD_TC(tp, update_mode_transitions);
	ATF_TP_ADD_TC(tp, baraddr_map_unmap);
	ATF_TP_ADD_TC(tp, render_paths);
#ifdef BHYVE_SNAPSHOT
	ATF_TP_ADD_TC(tp, snapshot_save_restore);
	ATF_TP_ADD_TC(tp, snapshot_argument_guards);
	ATF_TP_ADD_TC(tp, snapshot_validate);
#endif
	ATF_TP_ADD_TC(tp, devemu_registration);
	return (atf_no_error());
}
