/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * The bsdextension(8) hardware-driver class: device_drivers in the policy
 * permits a module that the kernel's linker.hints records with plug-and-play
 * match data (what devmatch(8) selects), unless an administrator override
 * denies it.  Pure unit cases over synthetic hints images, the policy parser
 * and the persistent override store, plus the installed kernel's hints.  No
 * capability plane, no kldload, no privilege.
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bsdextension.h"

struct image {
	unsigned char buf[4096];
	size_t len, rec;
};

static void
put_int(struct image *im, int v)
{
	im->len = roundup2(im->len, sizeof(int));
	ATF_REQUIRE(im->len + sizeof(int) <= sizeof(im->buf));
	memcpy(im->buf + im->len, &v, sizeof(int));
	im->len += sizeof(int);
}

static void
put_str(struct image *im, const char *s)
{
	size_t n = strlen(s);

	ATF_REQUIRE(n < 256 && im->len + 1 + n <= sizeof(im->buf));
	im->buf[im->len++] = (unsigned char)n;
	memcpy(im->buf + im->len, s, n);
	im->len += n;
}

/* kldxref(8): an aligned length word, then the record from its type on. */
static void
begin(struct image *im, int type)
{
	im->len = roundup2(im->len, sizeof(int));
	im->rec = im->len;
	put_int(im, 0);
	put_int(im, type);
}

static void
end(struct image *im)
{
	int reclen = (int)(im->len - im->rec - sizeof(int));

	memcpy(im->buf + im->rec, &reclen, sizeof(int));
}

static void
module(struct image *im, const char *name, const char *file)
{
	begin(im, MDT_MODULE);
	put_str(im, name);
	put_str(im, file);
	end(im);
}

static void
pnp(struct image *im, const char *bus)
{
	begin(im, MDT_PNP_INFO);
	put_str(im, bus);
	put_str(im, "U16:vendor;U16:product;");
	put_int(im, 1);
	put_int(im, 0x46f4);
	end(im);
}

static void
build(struct image *im)
{
	memset(im, 0, sizeof(*im));
	put_int(im, LINKER_HINTS_VERSION);
	module(im, "uaudio", "kernel");		/* built in: not loadable */
	pnp(im, "uhub");
	module(im, "snd_uaudio", "snd_uaudio.ko");
	pnp(im, "uhub");
	module(im, "zfsctrl", "zfs.ko");		/* no PNP tables */
	module(im, "if_ure", "if_ure.ko");
	pnp(im, "uhub");
}

ATF_TC_WITHOUT_HEAD(hints_classify);
ATF_TC_BODY(hints_classify, tc)
{
	struct image im;

	build(&im);
	ATF_CHECK(sysext_hints_pnp_module(im.buf, im.len, "snd_uaudio"));
	ATF_CHECK(sysext_hints_pnp_module(im.buf, im.len, "snd_uaudio.ko"));
	ATF_CHECK(sysext_hints_pnp_module(im.buf, im.len, "if_ure"));
	/* A module without PNP data, the kernel itself, and strangers. */
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, "zfs"));
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, "kernel"));
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, "uaudio"));
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, "mac_ntpd"));
	/* Names that are not a single safe component never match. */
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, "../snd_uaudio"));
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, ""));
}

ATF_TC_WITHOUT_HEAD(hints_malformed);
ATF_TC_BODY(hints_malformed, tc)
{
	struct image im;
	size_t i;
	int v;

	build(&im);
	/* Every truncation is bounded; none may read past the image. */
	for (i = 0; i < im.len; i++)
		(void)sysext_hints_pnp_module(im.buf, i, "if_ure");
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, 0, "snd_uaudio"));
	/* Wrong version. */
	v = LINKER_HINTS_VERSION + 1;
	memcpy(im.buf, &v, sizeof(v));
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, "snd_uaudio"));
	/* A record length past the end stops the walk. */
	build(&im);
	v = (int)im.len;
	memcpy(im.buf + sizeof(int), &v, sizeof(v));
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, "snd_uaudio"));
	/* A string length past its record does not name a file. */
	build(&im);
	for (i = sizeof(int); i + 10 < im.len; i++)
		if (memcmp(im.buf + i + 1, "snd_uaudio.ko", 13) == 0 &&
		    im.buf[i] == 13)
			break;
	ATF_REQUIRE(i + 10 < im.len);
	im.buf[i] = 200;
	ATF_CHECK(!sysext_hints_pnp_module(im.buf, im.len, "snd_uaudio"));
	ATF_CHECK(sysext_hints_pnp_module(im.buf, im.len, "if_ure"));
}

static const char *
write_conf(const char *content)
{
	static char path[64];
	size_t len = strlen(content);
	int fd;

	strlcpy(path, "conf.XXXXXX", sizeof(path));
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, content, len));
	ATF_REQUIRE_EQ(0, close(fd));
	return (path);
}

ATF_TC_WITHOUT_HEAD(policy_key);
ATF_TC_BODY(policy_key, tc)
{
	static const char *invalid[] = {
	    "device_drivers = \"yes\"; allowed_extensions = [];",
	    "device_drivers = 1; allowed_extensions = [];",
	    "device_drivers = true;",
	    "device_drivers = true; allowed_extensions = []; extra = 1;",
	    "devices = true; allowed_extensions = [];",
	    "device_drivers = true; device_drivers = false; allowed_extensions = [];",
	};
	struct sysext_config cfg;
	size_t i;

	sysext_config_defaults(&cfg);
	ATF_CHECK(!cfg.device_drivers);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg,
	    write_conf("device_drivers = true;\nallowed_extensions = [\"a\"];")));
	ATF_CHECK(cfg.device_drivers);
	ATF_CHECK_EQ(1, cfg.nallow);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg,
	    write_conf("device_drivers = false; allowed_extensions = [];")));
	ATF_CHECK(!cfg.device_drivers);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg,
	    write_conf("allowed_extensions = [];")));
	ATF_CHECK(!cfg.device_drivers);
	for (i = 0; i < nitems(invalid); i++) {
		sysext_config_defaults(&cfg);
		ATF_CHECK_MSG(sysext_config_load(&cfg,
		    write_conf(invalid[i])) == -1, "accepted: %s", invalid[i]);
		ATF_CHECK(!cfg.device_drivers);
	}
}

/* The flag survives resolution and reload; an override deny beats it. */
ATF_TC_WITHOUT_HEAD(deny_override);
ATF_TC_BODY(deny_override, tc)
{
	struct sysext_config cfg;
	struct sysext_policy *policy;
	int dirfd;

	sysext_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg,
	    write_conf("device_drivers = true; allowed_extensions = [];")));
	policy = sysext_policy_create(&cfg);
	ATF_REQUIRE(policy != NULL);
	ATF_REQUIRE_EQ(0, mkdir("state", 0700));
	dirfd = open("state", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dirfd >= 0);
	ATF_REQUIRE_EQ(0, sysext_policy_attach(policy, dirfd));
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(policy, &cfg));
	ATF_CHECK(cfg.device_drivers);
	ATF_CHECK(!sysext_policy_denied(policy, "snd_uaudio"));
	ATF_REQUIRE_EQ(0, sysext_policy_change(policy, SYSEXT_OP_DENY,
	    "snd_uaudio", SERVICE_RIGHTS_ADMIN));
	ATF_CHECK(sysext_policy_denied(policy, "snd_uaudio"));
	ATF_CHECK(!sysext_policy_denied(policy, "if_ure"));
	ATF_REQUIRE_EQ(0, sysext_policy_change(policy, SYSEXT_OP_RESET,
	    "snd_uaudio", SERVICE_RIGHTS_ADMIN));
	ATF_CHECK(!sysext_policy_denied(policy, "snd_uaudio"));
	/* A reload without the key turns the class off. */
	ATF_REQUIRE_EQ(0, sysext_policy_reload(policy,
	    write_conf("allowed_extensions = [];"), SERVICE_RIGHTS_ADMIN));
	ATF_REQUIRE_EQ(0, sysext_policy_snapshot(policy, &cfg));
	ATF_CHECK(!cfg.device_drivers);
	sysext_policy_destroy(policy);
	close(dirfd);
}

ATF_TC(installed_kernel);
ATF_TC_HEAD(installed_kernel, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The installed kernel's hints classify its drivers");
}
ATF_TC_BODY(installed_kernel, tc)
{
	const char *dir;
	int dirfd;

	dir = atf_tc_get_config_var_wd(tc, "kernel_dir", SYSEXT_KERNEL_DIR);
	dirfd = open(dir, O_DIRECTORY | O_RDONLY);
	if (dirfd == -1 || faccessat(dirfd, "linker.hints", R_OK, 0) == -1)
		atf_tc_skip("no readable %s/linker.hints", dir);
	if (faccessat(dirfd, "snd_uaudio.ko", R_OK, 0) == 0)
		ATF_CHECK(sysext_driver_module(dirfd, "snd_uaudio"));
	if (faccessat(dirfd, "if_ure.ko", R_OK, 0) == 0)
		ATF_CHECK(sysext_driver_module(dirfd, "if_ure"));
	/* Service modules carry no PNP data and need an allow-list entry. */
	ATF_CHECK(!sysext_driver_module(dirfd, "mac_ntpd"));
	ATF_CHECK(!sysext_driver_module(dirfd, "zfs"));
	ATF_CHECK(!sysext_driver_module(dirfd, "nonexistent_module"));
	ATF_CHECK(!sysext_driver_module(-1, "snd_uaudio"));
	close(dirfd);
}

ATF_TC(packaged_policy);
ATF_TC_HEAD(packaged_policy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The packaged policy enables the driver class and lists the rc.d "
	    "service modules");
}
ATF_TC_BODY(packaged_policy, tc)
{
	static const char *service[] = { "mac_ntpd", "if_vlan", "geom_uzip",
	    "nfscl", "nfsd", "cuse", "kbdmux", "vkbd", "ng_btsocket" };
	struct sysext_config cfg;
	const char *path;
	size_t i;

	path = atf_tc_get_config_var_wd(tc, "packaged_policy",
	    "/Capabilities/System/SystemExtension.cap/Units/bsdextension.unit/Config/bsdextension.ucl");
	if (access(path, R_OK) == -1)
		atf_tc_skip("no packaged policy at %s", path);
	sysext_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg, path));
	ATF_CHECK(cfg.device_drivers);
	for (i = 0; i < nitems(service); i++)
		ATF_CHECK_MSG(extension_allowed(&cfg, service[i]),
		    "%s is not allow-listed", service[i]);
	/* devd's lasting grant is limited to the hardware-driver class. */
	ATF_CHECK(sysext_driver_client(&cfg, "devd"));
	ATF_CHECK(!sysext_driver_client(&cfg, "etc-rc"));
}

/*
 * driver_clients: optional array of switchboard client labels limited to the
 * hardware-driver class.  Unique, bounded, label syntax only; every other
 * shape refuses the whole policy.
 */
ATF_TC_WITHOUT_HEAD(driver_clients_key);
ATF_TC_BODY(driver_clients_key, tc)
{
	static const char *bad[] = {
	    "driver_clients = \"devd\"; allowed_extensions = [];",
	    "driver_clients = [1]; allowed_extensions = [];",
	    "driver_clients = [\"\"]; allowed_extensions = [];",
	    "driver_clients = [\"..\"]; allowed_extensions = [];",
	    "driver_clients = [\"a/b\"]; allowed_extensions = [];",
	    "driver_clients = [\"a b\"]; allowed_extensions = [];",
	    "driver_clients = [\"devd\", \"devd\"]; allowed_extensions = [];",
	    "driver_clients = [\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\"];"
	    " allowed_extensions = [];",
	    "driver_clients = [\"devd\"];",
	    "driver_clients = [\"devd\"]; device_drivers = true;",
	    "driver_clients = [\"devd\"]; device_drivers = true;"
	    " allowed_extensions = []; extra = 1;",
	    "driver_clients = []; driver_clients = []; allowed_extensions = [];",
	};
	struct sysext_config cfg;
	size_t i;

	(void)tc;
	sysext_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg, write_conf(
	    "device_drivers = true;\ndriver_clients = [\"devd\", \"x.y-z_1\"];\n"
	    "allowed_extensions = [\"a\"];")));
	ATF_CHECK(cfg.device_drivers);
	ATF_CHECK_EQ(2, cfg.ndriver_clients);
	ATF_CHECK(sysext_driver_client(&cfg, "devd"));
	ATF_CHECK(sysext_driver_client(&cfg, "x.y-z_1"));
	ATF_CHECK(!sysext_driver_client(&cfg, "dev"));
	ATF_CHECK(!sysext_driver_client(&cfg, NULL));
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg, write_conf(
	    "driver_clients = []; allowed_extensions = [];")));
	ATF_CHECK_EQ(0, cfg.ndriver_clients);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg, write_conf(
	    "allowed_extensions = [];")));
	ATF_CHECK_EQ(0, cfg.ndriver_clients);
	for (i = 0; i < nitems(bad); i++) {
		sysext_config_defaults(&cfg);
		ATF_CHECK_MSG(sysext_config_load(&cfg, write_conf(bad[i])) == -1,
		    "accepted: %s", bad[i]);
		ATF_CHECK_EQ(0, cfg.ndriver_clients);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hints_classify);
	ATF_TP_ADD_TC(tp, hints_malformed);
	ATF_TP_ADD_TC(tp, policy_key);
	ATF_TP_ADD_TC(tp, deny_override);
	ATF_TP_ADD_TC(tp, installed_kernel);
	ATF_TP_ADD_TC(tp, packaged_policy);
	ATF_TP_ADD_TC(tp, driver_clients_key);
	return (atf_no_error());
}
