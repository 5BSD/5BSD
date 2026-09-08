/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Daemon-wiring tests: blued.c, the daemon main() translation unit.
 *
 * blued_daemon_stub.c stands in for blued.c so blued_event.c /
 * blued_peripheral.c / blued_central.c can be linked; the consequence was that
 * blued.c's OWN statics -- the bond-database quarantine, the persisted-settings
 * restore validation, the SIGHUP reload arms, the resolving-list programming --
 * were reached by no test at all.
 *
 * Measurement (nm(1) over the production objects): the only global blued.c
 * defines that nothing else in the daemon also defines is main(); every symbol
 * it references and does not define resolves against another production
 * translation unit or against libc / libutil / libbsm / libbluetooth /
 * libservice.  So this program needs NO stub: it #include's the shipping unit
 * with main() renamed (the cli_test.c / cli_meshctl_test.c / meshd_main_test.c
 * pattern) and links the real rest of the daemon.
 *
 * The controller is observed through the established --wrap=bt_devreq seam;
 * --wrap=syslog makes the BLUED_LOG_SECURITY audit record observable, since
 * that macro writes to syslog unconditionally and to stderr only when verbose.
 *
 * Each case names the correctness fix it pins.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>

#define main blued_main_unused
#include "blued.c"
#undef main

#include <atf-c.h>

/* ================================================================
 * bt_devreq seam: count commands, script per-opcode controller status.
 * ================================================================ */

#define	BMT_MAX_CMDS	64

static struct {
	unsigned int	ncalls;
	uint16_t	opcode[BMT_MAX_CMDS];
	/* Per-opcode scripted Command Complete status (0 = success). */
	uint16_t	fail_opcode;
	uint8_t		fail_status;
	/* LE Read Resolving List Size reply. */
	uint8_t		rl_size;
	/* Transport-level failure for one opcode (bt_devreq returns -1). */
	uint16_t	xport_fail_opcode;
} bmt_hci;

int	__wrap_bt_devreq(int s, struct bt_devreq *r, time_t to);
void	__wrap_syslog(int pri, const char *fmt, ...) __printflike(2, 3);

int
__wrap_bt_devreq(int s __unused, struct bt_devreq *r, time_t to __unused)
{
	uint8_t *rp = r->rparam;

	if (bmt_hci.ncalls < BMT_MAX_CMDS)
		bmt_hci.opcode[bmt_hci.ncalls] = r->opcode;
	bmt_hci.ncalls++;

	if (bmt_hci.xport_fail_opcode != 0 &&
	    r->opcode == bmt_hci.xport_fail_opcode) {
		errno = EIO;
		return (-1);
	}
	if (rp == NULL || r->rlen == 0)
		return (0);
	memset(rp, 0, r->rlen);
	if (bmt_hci.fail_opcode != 0 && r->opcode == bmt_hci.fail_opcode)
		rp[0] = bmt_hci.fail_status;
	if (r->opcode == NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_READ_RESOLVING_LIST_SIZE) && r->rlen >= 2)
		rp[1] = bmt_hci.rl_size;
	return (0);
}

/* Was a given opcode issued at all? */
static bool
bmt_saw(uint16_t opcode)
{
	unsigned int i, n = bmt_hci.ncalls;

	if (n > BMT_MAX_CMDS)
		n = BMT_MAX_CMDS;
	for (i = 0; i < n; i++)
		if (bmt_hci.opcode[i] == opcode)
			return (true);
	return (false);
}

/* ================================================================
 * syslog seam: BLUED_LOG_SECURITY observation.
 * ================================================================ */

static struct {
	unsigned int	ncalls;
	int		last_pri;
	char		last[512];
} bmt_log;

void
__wrap_syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	bmt_log.ncalls++;
	bmt_log.last_pri = pri;
	va_start(ap, fmt);
	(void)vsnprintf(bmt_log.last, sizeof(bmt_log.last), fmt, ap);
	va_end(ap);
}

/* ================================================================
 * Fixture
 * ================================================================ */

static void
bmt_reset(void)
{

	memset(&bmt_hci, 0, sizeof(bmt_hci));
	memset(&bmt_log, 0, sizeof(bmt_log));

	memset(&blued_g, 0, sizeof(blued_g));
	blued_g.kq = -1;
	blued_g.ctl_fd = -1;
	blued_g.bond_fd = -1;
	blued_g.bond_dirfd = -1;
	blued_g.bond_lockfd = -1;
	blued_g.config_fd = -1;
	blued_g.config_dirfd = -1;
	blued_g.persist_dirfd = -1;
	blued_g.vhid_ctl_fd = -1;
	LIST_INIT(&blued_g.adapters);
	LIST_INIT(&blued_g.conns);
	LIST_INIT(&blued_g.ctl_clients);
	LIST_INIT(&blued_g.ctl_acquires);
	pthread_rwlock_init(&blued_g.conns_lock, NULL);
	pthread_mutex_init(&blued_g.bond_db_lock, NULL);
	pthread_mutex_init(&blued_g.gatt_db_lock, NULL);
	pthread_mutex_init(&blued_g.att_sec_lock, NULL);
	pthread_mutex_init(&blued_g.reslist_lock, NULL);
	blued_g.main_thread = pthread_self();

	blued_config_defaults(&blued_cfg);
	blued_config_path = NULL;
	blued_saved_argc = 0;
	blued_saved_argv = NULL;
	blued_runtime_resolv_count = 0;
	memset(blued_runtime_resolv, 0, sizeof(blued_runtime_resolv));
	blued_rpa_timer = 0;
	blued_rpa_retry_timer = 0;
	blued_has_local_irk = false;
	memset(blued_local_irk, 0, sizeof(blued_local_irk));
	blued_reconnect_max_delay = 60;
	blued_verbose = 0;
	blued_daemonized = 0;
}

/* Number of "<base>.rejected.*" entries in dir. */
static int
bmt_count_rejected(const char *dir, const char *base)
{
	char prefix[NAME_MAX + 1];
	struct dirent *de;
	DIR *d;
	int n = 0;

	(void)snprintf(prefix, sizeof(prefix), "%s.rejected.", base);
	d = opendir(dir);
	if (d == NULL)
		return (-1);
	while ((de = readdir(d)) != NULL)
		if (strncmp(de->d_name, prefix, strlen(prefix)) == 0)
			n++;
	(void)closedir(d);
	return (n);
}

/*
 * Anchor the database exactly as main() does (blued_bond_set_atomic() runs
 * before blued_bond_load_or_quarantine()): the per-database secret is looked
 * up through dir_fd + file_name, so an unanchored database fails every load at
 * key derivation instead of at the gate a case is aiming at.
 */
static void
bmt_bond_db_init(struct smp_bond_db *db, int dirfd, const char *path)
{

	memset(db, 0, sizeof(*db));
	db->fd = -1;
	smp_bond_db_set_atomic(db, dirfd, path);
	ATF_REQUIRE_MSG(db->dir_fd >= 0, "the database must be anchored");
}

static void
bmt_fill_bond(struct smp_bond *b, uint8_t tag)
{

	memset(b, 0, sizeof(*b));
	b->addr[0] = tag;
	b->addr[1] = 0x22;
	b->addr[2] = 0x33;
	b->addr[3] = 0x44;
	b->addr[4] = 0x55;
	b->addr[5] = 0x66;
	b->addr_type = BDADDR_LE_RANDOM;
	memset(b->ltk, 0xAB, sizeof(b->ltk));
	b->has_ltk = true;
	memset(b->irk, 0xCD, sizeof(b->irk));
	b->irk[0] = tag;
	b->has_irk = true;
	b->key_size = 16;
}

/*
 * Build a bond database file that this build CANNOT load, without touching the
 * ciphertext: the on-disk header is
 *   uint8_t[5] "BONDE" | uint32_t version (LE) | salt | IV | tag | ct_len
 * and the version is not part of the GCM AAD, so patching it to a superseded
 * BOND_ENC_VERSION leaves a perfectly decryptable file whose ONLY defect is
 * the version gate in smp_bond_db_load().  That is exactly the "unusable by
 * this build" condition the quarantine exists for.
 */
#define	BMT_BOND_MAGIC_BYTES	5
#define	BMT_BOND_SUPERSEDED_VER	5

static int
bmt_make_bond_file(const char *dir, const char *base, char *path, size_t plen,
    bool downgrade)
{
	struct smp_bond_db db;
	struct smp_bond b;
	uint32_t ver_le;
	int dirfd, fd;

	(void)snprintf(path, plen, "%s/%s", dir, base);
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dirfd >= 0);
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	ATF_REQUIRE(fd >= 0);

	memset(&db, 0, sizeof(db));
	db.fd = fd;
	smp_bond_db_set_atomic(&db, dirfd, path);
	bmt_fill_bond(&b, 0x11);
	ATF_REQUIRE_EQ(0, smp_bond_db_store(&db, &b));
	ATF_REQUIRE_EQ(1, db.count);

	if (downgrade) {
		ver_le = htole32(BMT_BOND_SUPERSEDED_VER);
		ATF_REQUIRE_EQ((ssize_t)sizeof(ver_le),
		    pwrite(fd, &ver_le, sizeof(ver_le), BMT_BOND_MAGIC_BYTES));
	}
	(void)close(fd);
	(void)close(dirfd);

	/* Hand back a caller-owned descriptor, as main() would hold. */
	fd = open(path, O_RDWR | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

/* ================================================================
 * blued_bond_load_or_quarantine() -- C3-L19.
 *
 * Before the fix every load failure was err(1): a BOND_ENC_VERSION bump made
 * blued REFUSE TO BOOT, on a machine whose only input device may be the HID
 * peer in that very database.  The contract now is: rename the file aside,
 * KEEP it, log at security level, continue with an empty database.
 * ================================================================ */

ATF_TC_WITHOUT_HEAD(quarantine_renames_unusable_db_aside);
ATF_TC_BODY(quarantine_renames_unusable_db_aside, tc)
{
	struct smp_bond_db db;
	char dir[] = "/tmp/blued_bmt_q1.XXXXXX";
	char path[PATH_MAX];
	int fd;

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	fd = bmt_make_bond_file(dir, "bonds", path, sizeof(path), true);
	blued_g.bond_dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(blued_g.bond_dirfd >= 0);

	bmt_bond_db_init(&db, blued_g.bond_dirfd, path);
	ATF_CHECK_EQ_MSG(0, blued_bond_load_or_quarantine(&db, &fd, path),
	    "an unusable bond database must not fail the daemon start");
	ATF_CHECK_EQ_MSG(1, bmt_count_rejected(dir, "bonds"),
	    "the unusable database must be renamed to bonds.rejected.<epoch>");

	(void)close(fd);
	(void)close(blued_g.bond_dirfd);
}

ATF_TC_WITHOUT_HEAD(quarantine_keeps_the_rejected_database);
ATF_TC_BODY(quarantine_keeps_the_rejected_database, tc)
{
	struct smp_bond_db db;
	struct stat before, after;
	char dir[] = "/tmp/blued_bmt_q2.XXXXXX";
	char path[PATH_MAX], rej[PATH_MAX];
	struct dirent *de;
	DIR *d;
	int fd;

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	fd = bmt_make_bond_file(dir, "bonds", path, sizeof(path), true);
	ATF_REQUIRE_EQ(0, stat(path, &before));
	ATF_REQUIRE(before.st_size > 0);
	blued_g.bond_dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(blued_g.bond_dirfd >= 0);

	bmt_bond_db_init(&db, blued_g.bond_dirfd, path);
	ATF_REQUIRE_EQ(0, blued_bond_load_or_quarantine(&db, &fd, path));

	rej[0] = '\0';
	d = opendir(dir);
	ATF_REQUIRE(d != NULL);
	while ((de = readdir(d)) != NULL)
		if (strncmp(de->d_name, "bonds.rejected.", 15) == 0)
			(void)snprintf(rej, sizeof(rej), "%s/%s", dir,
			    de->d_name);
	(void)closedir(d);

	ATF_REQUIRE_MSG(rej[0] != '\0', "no quarantined file was produced");
	ATF_REQUIRE_EQ(0, stat(rej, &after));
	ATF_CHECK_EQ_MSG(before.st_ino, after.st_ino,
	    "the rejected database must be the SAME inode, renamed aside");
	ATF_CHECK_EQ_MSG(before.st_size, after.st_size,
	    "the rejected database must be kept intact, never truncated");

	(void)close(fd);
	(void)close(blued_g.bond_dirfd);
}

ATF_TC_WITHOUT_HEAD(quarantine_continues_with_an_empty_database);
ATF_TC_BODY(quarantine_continues_with_an_empty_database, tc)
{
	struct smp_bond_db db;
	struct stat old_st, new_st;
	char dir[] = "/tmp/blued_bmt_q3.XXXXXX";
	char path[PATH_MAX];
	int fd, old_fd;

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	fd = bmt_make_bond_file(dir, "bonds", path, sizeof(path), true);
	old_fd = fd;
	ATF_REQUIRE_EQ(0, fstat(fd, &old_st));
	blued_g.bond_dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(blued_g.bond_dirfd >= 0);

	bmt_bond_db_init(&db, blued_g.bond_dirfd, path);
	ATF_REQUIRE_EQ(0, blued_bond_load_or_quarantine(&db, &fd, path));

	ATF_CHECK_EQ_MSG(0, db.count,
	    "the daemon must continue with an EMPTY database (peers re-pair)");
	ATF_CHECK_MSG(fd >= 0, "*fdp must be a usable descriptor afterwards");
	ATF_CHECK_MSG(fd != old_fd || old_st.st_ino != 0,
	    "the caller's descriptor must be replaced, not reused blindly");
	ATF_REQUIRE_EQ(0, fstat(fd, &new_st));
	ATF_CHECK_EQ_MSG(0, new_st.st_size,
	    "the replacement descriptor must be on a freshly created file");
	ATF_CHECK_MSG(old_st.st_ino != new_st.st_ino,
	    "renameat() leaves the old fd on the quarantined inode; the "
	    "replacement must be a different inode");
	ATF_CHECK_EQ_MSG(0, stat(path, &new_st),
	    "the live bond database path must exist again");

	(void)close(fd);
	(void)close(blued_g.bond_dirfd);
}

ATF_TC_WITHOUT_HEAD(quarantine_logs_at_security_level);
ATF_TC_BODY(quarantine_logs_at_security_level, tc)
{
	struct smp_bond_db db;
	char dir[] = "/tmp/blued_bmt_q4.XXXXXX";
	char path[PATH_MAX];
	int fd;

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	fd = bmt_make_bond_file(dir, "bonds", path, sizeof(path), true);
	blued_g.bond_dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(blued_g.bond_dirfd >= 0);

	memset(&bmt_log, 0, sizeof(bmt_log));
	bmt_bond_db_init(&db, blued_g.bond_dirfd, path);
	ATF_REQUIRE_EQ(0, blued_bond_load_or_quarantine(&db, &fd, path));

	ATF_CHECK_MSG(bmt_log.ncalls > 0,
	    "discarding a bond database is a security event and must be "
	    "logged unconditionally, not only when verbose");
	ATF_CHECK_EQ_MSG(LOG_AUTH | LOG_NOTICE, bmt_log.last_pri,
	    "BLUED_LOG_SECURITY must use the LOG_AUTH audit facility");
	ATF_CHECK_MSG(strstr(bmt_log.last, "unusable") != NULL,
	    "the record must say the database was unusable: got \"%s\"",
	    bmt_log.last);
	ATF_CHECK_MSG(strstr(bmt_log.last, ".rejected.") != NULL,
	    "the record must name the file the operator can recover: \"%s\"",
	    bmt_log.last);

	(void)close(fd);
	(void)close(blued_g.bond_dirfd);
}

ATF_TC_WITHOUT_HEAD(quarantine_leaves_a_good_database_untouched);
ATF_TC_BODY(quarantine_leaves_a_good_database_untouched, tc)
{
	struct smp_bond_db db;
	char dir[] = "/tmp/blued_bmt_q5.XXXXXX";
	char path[PATH_MAX];
	int fd, saved_fd;

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	fd = bmt_make_bond_file(dir, "bonds", path, sizeof(path), false);
	saved_fd = fd;
	blued_g.bond_dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(blued_g.bond_dirfd >= 0);

	bmt_bond_db_init(&db, blued_g.bond_dirfd, path);
	ATF_CHECK_EQ_MSG(0, blued_bond_load_or_quarantine(&db, &fd, path),
	    "a good database must load");
	ATF_CHECK_EQ_MSG(1, db.count, "the stored bond must be surfaced");
	ATF_CHECK_EQ_MSG(saved_fd, fd,
	    "a successful load must not replace the caller's descriptor");
	ATF_CHECK_EQ_MSG(0, bmt_count_rejected(dir, "bonds"),
	    "a good database must never be renamed aside");
	ATF_CHECK_EQ_MSG(0, bmt_log.ncalls,
	    "a good database must emit no security record");

	(void)close(fd);
	(void)close(blued_g.bond_dirfd);
}

ATF_TC_WITHOUT_HEAD(quarantine_fails_closed_without_a_directory_fd);
ATF_TC_BODY(quarantine_fails_closed_without_a_directory_fd, tc)
{
	struct smp_bond_db db;
	struct stat before, after;
	char dir[] = "/tmp/blued_bmt_q6.XXXXXX";
	char path[PATH_MAX];
	int dirfd, fd;

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	fd = bmt_make_bond_file(dir, "bonds", path, sizeof(path), true);
	ATF_REQUIRE_EQ(0, stat(path, &before));
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(dirfd >= 0);
	blued_g.bond_dirfd = -1;

	bmt_bond_db_init(&db, dirfd, path);
	ATF_CHECK_EQ_MSG(-1, blued_bond_load_or_quarantine(&db, &fd, path),
	    "without a directory fd the quarantine cannot rename atomically "
	    "and must report failure rather than pretend to have recovered");
	ATF_CHECK_EQ_MSG(0, stat(path, &after),
	    "the database must be left in place");
	ATF_CHECK_EQ(before.st_ino, after.st_ino);
	ATF_CHECK_EQ_MSG(0, bmt_count_rejected(dir, "bonds"),
	    "nothing may be renamed aside without the directory fd");

	(void)close(fd);
	(void)close(dirfd);
}

/* ================================================================
 * blued_persist_settings_to_cfg() -- persisted-settings restore.
 * ================================================================ */

/*
 * C3-M10.  io_capability was the one restored field with no range check.  An
 * out-of-range byte makes smp_select_model() return INVALID, so every pairing
 * fails -- permanently, across every restart, because the bad value is
 * re-persisted -- and the byte is also transmitted in the Pairing
 * Request/Response.
 */
ATF_TC_WITHOUT_HEAD(persist_restore_rejects_out_of_range_io_capability);
ATF_TC_BODY(persist_restore_rejects_out_of_range_io_capability, tc)
{
	struct blued_persist_settings s;
	struct blued_config cfg;
	static const uint8_t bad[] = { 0x05, 0x10, 0x7f, 0x80, 0xff };
	size_t i;

	bmt_reset();
	for (i = 0; i < nitems(bad); i++) {
		blued_config_defaults(&cfg);
		cfg.io_capability = SMP_IO_DISPLAY_YESNO;
		memset(&s, 0, sizeof(s));
		s.io_capability = bad[i];
		blued_persist_settings_to_cfg(&s, &cfg);
		ATF_CHECK_EQ_MSG(SMP_IO_DISPLAY_YESNO, cfg.io_capability,
		    "stored io_capability 0x%02x is out of range and must be "
		    "rejected, not assigned", bad[i]);
	}
}

ATF_TC_WITHOUT_HEAD(persist_restore_accepts_every_valid_io_capability);
ATF_TC_BODY(persist_restore_accepts_every_valid_io_capability, tc)
{
	struct blued_persist_settings s;
	struct blued_config cfg;
	uint8_t v;

	bmt_reset();
	for (v = SMP_IO_DISPLAY_ONLY; v <= SMP_IO_KEYBOARD_DISPLAY; v++) {
		blued_config_defaults(&cfg);
		cfg.io_capability = SMP_IO_NO_INPUT_NO_OUTPUT;
		memset(&s, 0, sizeof(s));
		s.io_capability = v;
		blued_persist_settings_to_cfg(&s, &cfg);
		ATF_CHECK_EQ_MSG(v, cfg.io_capability,
		    "the C3-M10 range check must not reject the valid value "
		    "0x%02x", v);
	}
}

/*
 * The other restored fields are range-checked too; an out-of-range stored
 * value must leave the live config alone rather than poison it.
 */
ATF_TC_WITHOUT_HEAD(persist_restore_range_gates_every_field);
ATF_TC_BODY(persist_restore_range_gates_every_field, tc)
{
	struct blued_persist_settings s;
	struct blued_config cfg;

	bmt_reset();
	blued_config_defaults(&cfg);
	cfg.privacy_mode = 1;
	cfg.sc_mode = BLUED_SC_ONLY;
	cfg.min_key_size = 16;
	cfg.rpa_timeout = 900;
	blued_g.att_preferred_mtu = 247;

	memset(&s, 0, sizeof(s));
	s.io_capability = SMP_IO_KEYBOARD_DISPLAY;
	s.privacy_mode = 9;
	s.sc_mode = 99;
	s.min_key_size = 6;
	s.rpa_timeout = 3601;
	s.preferred_mtu = 22;
	blued_persist_settings_to_cfg(&s, &cfg);

	ATF_CHECK_EQ_MSG(1, cfg.privacy_mode, "privacy_mode > 1 is invalid");
	ATF_CHECK_EQ_MSG(BLUED_SC_ONLY, cfg.sc_mode, "sc_mode 99 is invalid");
	ATF_CHECK_EQ_MSG(16, cfg.min_key_size,
	    "min_key_size 6 is below the Core Spec LE floor of 7 octets");
	ATF_CHECK_EQ_MSG(900, cfg.rpa_timeout, "rpa_timeout 3601 is invalid");
	ATF_CHECK_EQ_MSG(247, blued_g.att_preferred_mtu,
	    "an ATT MTU below the mandatory 23 must be rejected");

	/* And the in-range values are applied. */
	memset(&s, 0, sizeof(s));
	s.io_capability = SMP_IO_KEYBOARD_ONLY;
	s.privacy_mode = 0;
	s.sc_mode = BLUED_SC_ONLY;
	s.min_key_size = 7;
	s.rpa_timeout = 3600;
	s.preferred_mtu = 517;
	blued_persist_settings_to_cfg(&s, &cfg);
	ATF_CHECK_EQ(0, cfg.privacy_mode);
	ATF_CHECK_EQ(7, cfg.min_key_size);
	ATF_CHECK_EQ(3600, cfg.rpa_timeout);
	ATF_CHECK_EQ(517, blued_g.att_preferred_mtu);
}

/*
 * finding 67 (runtime discoverable state was saved but never restored) and
 * finding 140 (the runtime preferred ATT MTU had no persisted field at all and
 * reverted on every restart).
 */
ATF_TC_WITHOUT_HEAD(persist_restore_reinstates_discoverable_and_mtu);
ATF_TC_BODY(persist_restore_reinstates_discoverable_and_mtu, tc)
{
	struct blued_persist_settings s;
	struct blued_config cfg;

	bmt_reset();
	blued_config_defaults(&cfg);
	cfg.peripheral_mode = false;
	blued_g.att_preferred_mtu = 23;

	memset(&s, 0, sizeof(s));
	s.io_capability = SMP_IO_NO_INPUT_NO_OUTPUT;
	s.discoverable = 1;
	s.preferred_mtu = 185;
	blued_persist_settings_to_cfg(&s, &cfg);

	ATF_CHECK_MSG(cfg.peripheral_mode,
	    "a peripheral made discoverable at runtime must come back "
	    "discoverable after a restart");
	ATF_CHECK_EQ_MSG(185, blued_g.att_preferred_mtu,
	    "the runtime preferred ATT MTU must survive a restart");

	/* discoverable=0 must not force the mode OFF (it is one-way). */
	cfg.peripheral_mode = true;
	memset(&s, 0, sizeof(s));
	s.io_capability = SMP_IO_NO_INPUT_NO_OUTPUT;
	s.discoverable = 0;
	blued_persist_settings_to_cfg(&s, &cfg);
	ATF_CHECK_MSG(cfg.peripheral_mode,
	    "a stale discoverable=0 must not turn a configured peripheral off");
}

ATF_TC_WITHOUT_HEAD(persist_restore_ignores_an_empty_name);
ATF_TC_BODY(persist_restore_ignores_an_empty_name, tc)
{
	struct blued_persist_settings s;
	struct blued_config cfg;

	bmt_reset();
	blued_config_defaults(&cfg);
	strlcpy(cfg.peripheral_name, "FromTheConfigFile",
	    sizeof(cfg.peripheral_name));

	memset(&s, 0, sizeof(s));
	s.io_capability = SMP_IO_NO_INPUT_NO_OUTPUT;
	blued_persist_settings_to_cfg(&s, &cfg);
	ATF_CHECK_STREQ_MSG("FromTheConfigFile", cfg.peripheral_name,
	    "an empty persisted name must not blank the configured name");

	strlcpy(s.name, "RuntimeName", sizeof(s.name));
	blued_persist_settings_to_cfg(&s, &cfg);
	ATF_CHECK_STREQ_MSG("RuntimeName", cfg.peripheral_name,
	    "a name changed at runtime must win over the config file");
}

ATF_TC_WITHOUT_HEAD(persist_settings_round_trip);
ATF_TC_BODY(persist_settings_round_trip, tc)
{
	struct blued_persist_settings s;
	struct blued_config in, out;

	bmt_reset();
	blued_config_defaults(&in);
	strlcpy(in.peripheral_name, "RoundTrip", sizeof(in.peripheral_name));
	in.privacy = true;
	in.privacy_mode = 1;
	in.peripheral_mode = true;
	in.io_capability = SMP_IO_KEYBOARD_DISPLAY;
	in.bondable = false;
	in.sc_mode = BLUED_SC_ONLY;
	in.min_key_size = 12;
	in.rpa_timeout = 300;
	blued_g.att_preferred_mtu = 247;

	blued_persist_settings_from_cfg(&s, &in);
	blued_config_defaults(&out);
	blued_g.att_preferred_mtu = 23;
	blued_persist_settings_to_cfg(&s, &out);

	ATF_CHECK_STREQ("RoundTrip", out.peripheral_name);
	ATF_CHECK(out.privacy);
	ATF_CHECK_EQ(1, out.privacy_mode);
	ATF_CHECK(out.peripheral_mode);
	ATF_CHECK_EQ(SMP_IO_KEYBOARD_DISPLAY, out.io_capability);
	ATF_CHECK(!out.bondable);
	ATF_CHECK_EQ(BLUED_SC_ONLY, out.sc_mode);
	ATF_CHECK_EQ(12, out.min_key_size);
	ATF_CHECK_EQ(300, out.rpa_timeout);
	ATF_CHECK_EQ_MSG(247, blued_g.att_preferred_mtu,
	    "the preferred ATT MTU must survive the save/restore round trip");
}

/* ================================================================
 * SIGHUP reload (blued_reload_config).
 * ================================================================ */

static void
bmt_write_file(const char *path, const char *text)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)strlen(text),
	    write(fd, text, strlen(text)));
	(void)close(fd);
}

/*
 * The CLI overrides recorded at startup must be re-applied on top of every
 * re-parsed file.  Before the fix the reload rebuilt the config from defaults
 * + file only, so the FIRST SIGHUP silently reverted every -v/-d/-r/-f/-L
 * override to the file's value.  Reload repeatedly: the override must survive
 * each one, not just the first.
 */
ATF_TC_WITHOUT_HEAD(reload_reapplies_saved_cli_overrides);
ATF_TC_BODY(reload_reapplies_saved_cli_overrides, tc)
{
	static char a0[] = "blued";
	static char a1[] = "-r";
	static char *argv[] = { a0, a1, NULL };
	char dir[] = "/tmp/blued_bmt_r1.XXXXXX";
	char path[PATH_MAX];
	int i;

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	(void)snprintf(path, sizeof(path), "%s/blued.conf", dir);
	bmt_write_file(path, "features { reconnect = false; }\n");

	blued_cfg.reconnect = false;
	blued_config_path = path;
	blued_config_preopen();
	blued_saved_argc = 2;
	blued_saved_argv = argv;

	for (i = 0; i < 3; i++) {
		blued_reload_config();
		ATF_CHECK_EQ_MSG(true, blued_cfg.reconnect,
		    "reload %d dropped the -r CLI override", i + 1);
	}

	if (blued_g.config_fd >= 0)
		(void)close(blued_g.config_fd);
	if (blued_g.config_dirfd >= 0)
		(void)close(blued_g.config_dirfd);
}

/*
 * C3-M14.  Config files are routinely REPLACED rather than rewritten (sed -i,
 * install(1), mv, pkg upgrade).  With only the fd cached at startup the reload
 * re-parsed the original inode and still logged "configuration reloaded".
 */
ATF_TC_WITHOUT_HEAD(reload_follows_a_replaced_config_inode);
ATF_TC_BODY(reload_follows_a_replaced_config_inode, tc)
{
	char dir[] = "/tmp/blued_bmt_r2.XXXXXX";
	char path[PATH_MAX], tmp[PATH_MAX];

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	(void)snprintf(path, sizeof(path), "%s/blued.conf", dir);
	(void)snprintf(tmp, sizeof(tmp), "%s/blued.conf.new", dir);
	bmt_write_file(path, "features { reconnect_max_delay = 30; }\n");

	blued_cfg.reconnect_max_delay = 30;
	blued_reconnect_max_delay = 30;
	blued_config_path = path;
	blued_config_preopen();
	ATF_REQUIRE_MSG(blued_g.config_dirfd >= 0,
	    "the reload needs the parent directory fd to re-open by name");

	/* Replace the file with a brand-new inode, as install(1) does. */
	bmt_write_file(tmp, "features { reconnect_max_delay = 45; }\n");
	ATF_REQUIRE_EQ(0, rename(tmp, path));

	blued_reload_config();
	ATF_CHECK_EQ_MSG(45, blued_cfg.reconnect_max_delay,
	    "the reload must openat() the basename afresh and see the new "
	    "inode, not the fd cached at startup");
	ATF_CHECK_EQ_MSG(45, blued_reconnect_max_delay,
	    "C3-H4: the live backoff ceiling is the global, not blued_cfg");

	if (blued_g.config_fd >= 0)
		(void)close(blued_g.config_fd);
	if (blued_g.config_dirfd >= 0)
		(void)close(blued_g.config_dirfd);
}

/*
 * The cached startup fd stays as the fallback when the directory fd is
 * unavailable (a pre-cap_enter open that failed): the reload must still work.
 */
ATF_TC_WITHOUT_HEAD(reload_falls_back_to_the_cached_descriptor);
ATF_TC_BODY(reload_falls_back_to_the_cached_descriptor, tc)
{
	char dir[] = "/tmp/blued_bmt_r3.XXXXXX";
	char path[PATH_MAX];

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	(void)snprintf(path, sizeof(path), "%s/blued.conf", dir);
	bmt_write_file(path, "features { reconnect_max_delay = 21; }\n");

	blued_config_path = path;
	blued_config_preopen();
	ATF_REQUIRE(blued_g.config_fd >= 0);
	if (blued_g.config_dirfd >= 0) {
		(void)close(blued_g.config_dirfd);
		blued_g.config_dirfd = -1;
	}
	blued_g.config_base[0] = '\0';

	blued_reload_config();
	ATF_CHECK_EQ_MSG(21, blued_cfg.reconnect_max_delay,
	    "with no directory fd the reload must use the cached fd");

	(void)close(blued_g.config_fd);
}

ATF_TC_WITHOUT_HEAD(reload_keeps_settings_when_the_file_will_not_parse);
ATF_TC_BODY(reload_keeps_settings_when_the_file_will_not_parse, tc)
{
	char dir[] = "/tmp/blued_bmt_r4.XXXXXX";
	char path[PATH_MAX];

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	(void)snprintf(path, sizeof(path), "%s/blued.conf", dir);
	bmt_write_file(path, "features { reconnect_max_delay = 33; }\n");
	blued_config_path = path;
	blued_config_preopen();
	blued_reload_config();
	ATF_REQUIRE_EQ(33, blued_cfg.reconnect_max_delay);

	bmt_write_file(path, "features { this is not ucl \"\"\"\n");
	blued_reload_config();
	ATF_CHECK_EQ_MSG(33, blued_cfg.reconnect_max_delay,
	    "an unparsable file must leave the running settings alone");

	if (blued_g.config_fd >= 0)
		(void)close(blued_g.config_fd);
	if (blued_g.config_dirfd >= 0)
		(void)close(blued_g.config_dirfd);
}

/*
 * C3-M12.  main() builds the running config as defaults + file + CLI + persist
 * overlay, but the reload rebuilt it without the overlay, so the persist-owned
 * fields it merely REPORTS as "restart required" compared the file value
 * against a live value the file never set -- logging a change on every reload,
 * forever, while a restart would in fact reproduce the live value.
 */
ATF_TC_WITHOUT_HEAD(reload_overlay_adopts_persist_owned_live_values);
ATF_TC_BODY(reload_overlay_adopts_persist_owned_live_values, tc)
{
	struct blued_config cand;

	bmt_reset();
	/* Live values as restored from the state file at startup. */
	blued_cfg.peripheral_mode = true;
	blued_cfg.privacy_mode = 1;

	/* A reload candidate built from defaults + file only. */
	blued_config_defaults(&cand);
	cand.peripheral_mode = false;
	cand.privacy_mode = 0;

	blued_persist_settings_overlay(&cand);
	ATF_CHECK_MSG(cand.peripheral_mode,
	    "the reload candidate must adopt the live discoverable state");
	ATF_CHECK_EQ_MSG(1, cand.privacy_mode,
	    "the reload candidate must adopt the live privacy_mode");

	/*
	 * The overlay is one-way for peripheral_mode: a file that DOES ask for
	 * peripheral mode while the live daemon is not discoverable must keep
	 * its own value, so the "restart required" diagnostic still fires.
	 */
	blued_cfg.peripheral_mode = false;
	blued_config_defaults(&cand);
	cand.peripheral_mode = true;
	blued_persist_settings_overlay(&cand);
	ATF_CHECK_MSG(cand.peripheral_mode,
	    "the overlay must not clear a peripheral_mode the file set");
}

/*
 * C3-H4 + C3-M11.  reconnect and reconnect_max_delay are snapshotted onto each
 * connection when it is allocated, and the live backoff ceiling is the
 * blued_reconnect_max_delay global -- the reload reached neither, so its log
 * line was a lie.  A connection already backed off past a NEW, lower ceiling
 * must be re-clamped on the current retry, not only after a successful
 * connect.
 */
ATF_TC_WITHOUT_HEAD(reload_pushes_reconnect_policy_onto_live_connections);
ATF_TC_BODY(reload_pushes_reconnect_policy_onto_live_connections, tc)
{
	static struct blued_conn c_plain, c_override;
	char dir[] = "/tmp/blued_bmt_r5.XXXXXX";
	char path[PATH_MAX];

	bmt_reset();
	ATF_REQUIRE(mkdtemp(dir) != NULL);
	(void)snprintf(path, sizeof(path), "%s/blued.conf", dir);
	bmt_write_file(path,
	    "features {\n"
	    "  reconnect = true;\n"
	    "  reconnect_max_delay = 5;\n"
	    "}\n"
	    "devices {\n"
	    "  \"aa:bb:cc:dd:ee:ff\" {\n"
	    "    type = \"random\";\n"
	    "    reconnect = false;\n"
	    "  }\n"
	    "}\n");

	memset(&c_plain, 0, sizeof(c_plain));
	memset(&c_override, 0, sizeof(c_override));
	c_plain.reconnect = false;
	c_plain.reconnect_delay = 40;
	c_override.reconnect = false;
	c_override.reconnect_delay = 40;
	ATF_REQUIRE(bt_aton("aa:bb:cc:dd:ee:ff", &c_override.dst) != 0);
	ATF_REQUIRE(bt_aton("11:22:33:44:55:66", &c_plain.dst) != 0);
	LIST_INSERT_HEAD(&blued_g.conns, &c_plain, entries);
	LIST_INSERT_HEAD(&blued_g.conns, &c_override, entries);

	blued_cfg.reconnect = false;
	blued_cfg.reconnect_max_delay = 60;
	blued_reconnect_max_delay = 60;
	blued_config_path = path;
	blued_config_preopen();

	blued_reload_config();

	ATF_CHECK_EQ_MSG(5, blued_reconnect_max_delay,
	    "C3-H4: the reload must assign the live backoff ceiling global");
	ATF_CHECK_EQ_MSG(5, c_plain.reconnect_delay,
	    "a connection backed off past the new ceiling must be re-clamped");
	ATF_CHECK_EQ_MSG(5, c_override.reconnect_delay,
	    "a connection backed off past the new ceiling must be re-clamped");
	ATF_CHECK_MSG(c_plain.reconnect,
	    "C3-M11: the global reconnect toggle must reach live connections");
	ATF_CHECK_MSG(!c_override.reconnect,
	    "an explicit per-device reconnect=false must not be clobbered by "
	    "the global toggle");

	LIST_REMOVE(&c_plain, entries);
	LIST_REMOVE(&c_override, entries);
	if (blued_g.config_fd >= 0)
		(void)close(blued_g.config_fd);
	if (blued_g.config_dirfd >= 0)
		(void)close(blued_g.config_dirfd);
}

/* ================================================================
 * Resolving-list programming (blued_privacy_program / blued_privacy_set).
 * ================================================================ */

#define	BMT_OP_ADD_RL		NG_HCI_OPCODE(NG_HCI_OGF_LE,		\
				    NG_HCI_OCF_LE_ADD_DEV_RESOLVING_LIST)
#define	BMT_OP_REMOVE_RL	NG_HCI_OPCODE(NG_HCI_OGF_LE,		\
				    NG_HCI_OCF_LE_REMOVE_DEV_RESOLVING_LIST)
#define	BMT_OP_PRIVACY_MODE	NG_HCI_OPCODE(NG_HCI_OGF_LE,		\
				    NG_HCI_OCF_LE_SET_PRIVACY_MODE)
#define	BMT_OP_RESOLUTION	NG_HCI_OPCODE(NG_HCI_OGF_LE,		\
				    NG_HCI_OCF_LE_SET_ADDR_RESOLUTION_ENABLE)
#define	BMT_OP_RPA_TIMEOUT	NG_HCI_OPCODE(NG_HCI_OGF_LE,		\
				    NG_HCI_OCF_LE_SET_RPA_TIMEOUT)

static struct blued_adapter bmt_adp;
static struct smp_bond_db bmt_db;

/* Adapter + bond database with `nbonds` IRK-carrying peers. */
static void
bmt_privacy_fixture(int nbonds)
{
	int i;

	memset(&bmt_adp, 0, sizeof(bmt_adp));
	bmt_adp.hci_fd = 7;
	bmt_adp.active = true;
	bmt_adp.powered = true;
	strlcpy(bmt_adp.name, "ubt0", sizeof(bmt_adp.name));
	LIST_INSERT_HEAD(&blued_g.adapters, &bmt_adp, entries);

	memset(&bmt_db, 0, sizeof(bmt_db));
	bmt_db.fd = -1;
	for (i = 0; i < nbonds; i++)
		bmt_fill_bond(&bmt_db.bonds[i], (uint8_t)(0xA0 + i));
	bmt_db.count = nbonds;
	blued_g.bond_db = &bmt_db;

	/* A usable local identity, without reaching the bond-db key store. */
	memset(blued_local_irk, 0x5A, sizeof(blued_local_irk));
	blued_has_local_irk = true;

	blued_g.kq = kqueue();
	ATF_REQUIRE(blued_g.kq >= 0);
	blued_cfg.privacy = true;
	blued_cfg.rpa_timeout = 900;
}

static void
bmt_privacy_teardown(void)
{

	LIST_REMOVE(&bmt_adp, entries);
	if (blued_g.kq >= 0)
		(void)close(blued_g.kq);
	blued_g.kq = -1;
	blued_g.bond_db = NULL;
}

/*
 * Controller resolving lists are small.  Exceeding one must NOT be fatal: it
 * used to abort with err(1) at startup as soon as the bonds outnumbered the
 * list, bricking the daemon.  Program min(controller size, shadow cap) and
 * leave the rest to host-based resolution.
 */
ATF_TC_WITHOUT_HEAD(privacy_program_respects_controller_capacity);
ATF_TC_BODY(privacy_program_respects_controller_capacity, tc)
{
	struct blued_reslist shadow;

	bmt_reset();
	bmt_privacy_fixture(4);
	bmt_hci.rl_size = 2;

	memset(&shadow, 0, sizeof(shadow));
	ATF_CHECK_EQ_MSG(0, blued_privacy_program(bmt_adp.hci_fd, true,
	    &shadow), "a full resolving list must not fail the transition");
	ATF_CHECK_EQ_MSG(2, shadow.count,
	    "exactly the controller's capacity may be programmed");

	bmt_privacy_teardown();
}

ATF_TC_WITHOUT_HEAD(privacy_program_clamps_to_the_host_shadow);
ATF_TC_BODY(privacy_program_clamps_to_the_host_shadow, tc)
{
	struct blued_reslist shadow;
	int n = BLUED_RESLIST_MAX + 4;

	bmt_reset();
	ATF_REQUIRE(n <= SMP_MAX_BONDS);
	bmt_privacy_fixture(n);
	/* A controller that reports a size the host shadow cannot hold. */
	bmt_hci.rl_size = 0xff;

	memset(&shadow, 0, sizeof(shadow));
	ATF_CHECK_EQ(0, blued_privacy_program(bmt_adp.hci_fd, true, &shadow));
	ATF_CHECK_EQ_MSG(BLUED_RESLIST_MAX, shadow.count,
	    "the host shadow cap bounds the programmed set");

	bmt_privacy_teardown();
}

/*
 * LE Set Privacy Mode is optional (BT 5.0 Vol 4 Part E Section 7.8.77): a 4.2
 * controller answers Unknown HCI Command (0x01), mapped to EOPNOTSUPP.  That
 * is a SKIP -- the entry is valid in the controller's default Network Privacy
 * mode -- and must not roll the entry back out.
 */
ATF_TC_WITHOUT_HEAD(privacy_program_skips_an_unsupported_privacy_mode);
ATF_TC_BODY(privacy_program_skips_an_unsupported_privacy_mode, tc)
{
	struct blued_reslist shadow;

	bmt_reset();
	bmt_privacy_fixture(3);
	bmt_hci.rl_size = 8;
	bmt_hci.fail_opcode = BMT_OP_PRIVACY_MODE;
	bmt_hci.fail_status = 0x01;		/* Unknown HCI Command */

	memset(&shadow, 0, sizeof(shadow));
	ATF_CHECK_EQ(0, blued_privacy_program(bmt_adp.hci_fd, true, &shadow));
	ATF_CHECK_EQ_MSG(3, shadow.count,
	    "an unsupported optional command must be skipped, not treated as "
	    "a programming failure");
	ATF_CHECK_MSG(!bmt_saw(BMT_OP_REMOVE_RL),
	    "no entry may be rolled back on Unknown HCI Command");

	bmt_privacy_teardown();
}

/*
 * C3-L21 and its set-privacy-mode twin: any OTHER Set Privacy Mode failure
 * must remove the entry that was just added, or the controller holds a record
 * the host shadow never tracks and the two diverge.
 */
ATF_TC_WITHOUT_HEAD(privacy_program_rolls_back_a_half_programmed_entry);
ATF_TC_BODY(privacy_program_rolls_back_a_half_programmed_entry, tc)
{
	struct blued_reslist shadow;

	bmt_reset();
	bmt_privacy_fixture(3);
	bmt_hci.rl_size = 8;
	bmt_hci.fail_opcode = BMT_OP_PRIVACY_MODE;
	bmt_hci.fail_status = 0x12;		/* Invalid HCI Parameters */

	memset(&shadow, 0, sizeof(shadow));
	ATF_CHECK_EQ_MSG(0, blued_privacy_program(bmt_adp.hci_fd, true,
	    &shadow), "a per-entry failure is logged, never fatal");
	ATF_CHECK_EQ_MSG(0, shadow.count,
	    "an entry the shadow does not record must not be programmed");
	ATF_CHECK_MSG(bmt_saw(BMT_OP_REMOVE_RL),
	    "the half-programmed controller entry must be removed again");

	bmt_privacy_teardown();
}

/*
 * C3-M6.  The runtime (non-bond) resolving-list entries an operator added over
 * the control socket were rebuilt only by the init path; the PRIVACY toggle
 * rebuilt the list from bonds ONLY, so an on->off->on cycle silently dropped
 * every operator-supplied IRK.
 */
ATF_TC_WITHOUT_HEAD(privacy_program_reprograms_runtime_resolv_entries);
ATF_TC_BODY(privacy_program_reprograms_runtime_resolv_entries, tc)
{
	struct blued_reslist shadow;

	bmt_reset();
	bmt_privacy_fixture(0);
	bmt_hci.rl_size = 8;

	blued_runtime_resolv_count = 2;
	memset(blued_runtime_resolv, 0, sizeof(blued_runtime_resolv));
	blued_runtime_resolv[0].addr[0] = 0xE1;
	blued_runtime_resolv[0].addr_type = BDADDR_LE_RANDOM;
	memset(blued_runtime_resolv[0].irk, 0x31, 16);
	blued_runtime_resolv[1].addr[0] = 0xE2;
	blued_runtime_resolv[1].addr_type = BDADDR_LE_PUBLIC;
	memset(blued_runtime_resolv[1].irk, 0x32, 16);

	memset(&shadow, 0, sizeof(shadow));
	ATF_CHECK_EQ(0, blued_privacy_program(bmt_adp.hci_fd, true, &shadow));
	ATF_CHECK_EQ_MSG(2, shadow.count,
	    "operator RESOLV_ADD entries must survive a privacy toggle");

	bmt_privacy_teardown();
}

/*
 * The toggle is transactional: when the reprogram fails, the controller must
 * be left on the policy that was live BEFORE the request, and the host shadow
 * must match it exactly.  Coming from privacy off, that is a disabled, empty
 * resolving list.
 */
ATF_TC_WITHOUT_HEAD(privacy_set_restores_the_previous_policy_on_failure);
ATF_TC_BODY(privacy_set_restores_the_previous_policy_on_failure, tc)
{
	bmt_reset();
	bmt_privacy_fixture(2);
	bmt_hci.rl_size = 8;
	bmt_adp.privacy = false;
	bmt_adp.reslist.count = 0;
	/* Fail one of the hard (non per-entry) commands. */
	bmt_hci.xport_fail_opcode = BMT_OP_RPA_TIMEOUT;

	ATF_CHECK_EQ_MSG(-1, blued_privacy_set(bmt_adp.hci_fd, true),
	    "a failed privacy transition must be reported");
	ATF_CHECK_EQ_MSG(0, bmt_adp.reslist.count,
	    "the shadow must match the restored (disabled, empty) list");
	ATF_CHECK_EQ_MSG(EIO, errno,
	    "the errno of the failing controller command must survive the "
	    "restore path");

	bmt_privacy_teardown();
}

ATF_TC_WITHOUT_HEAD(privacy_set_rejects_an_unknown_descriptor);
ATF_TC_BODY(privacy_set_rejects_an_unknown_descriptor, tc)
{
	bmt_reset();
	bmt_privacy_fixture(1);

	errno = 0;
	ATF_CHECK_EQ(-1, blued_privacy_set(-1, true));
	errno = 0;
	ATF_CHECK_EQ_MSG(-1, blued_privacy_set(bmt_adp.hci_fd + 1, true),
	    "a descriptor with no adapter must not program a controller");
	ATF_CHECK_EQ(ENODEV, errno);
	ATF_CHECK_EQ_MSG(0, bmt_hci.ncalls,
	    "no HCI command may be issued for an unknown adapter");

	bmt_privacy_teardown();
}

/*
 * H-H5: peer-RPA resolution is independent of LOCAL privacy.  Turning privacy
 * OFF while the resolving list still holds peer identities must leave address
 * resolution ENABLED, or a bonded peer advertising with an RPA can no longer
 * be resolved for auto-reconnect.
 */
ATF_TC_WITHOUT_HEAD(privacy_off_keeps_resolution_for_peer_identities);
ATF_TC_BODY(privacy_off_keeps_resolution_for_peer_identities, tc)
{
	struct blued_reslist shadow;
	uint8_t addr[6] = { 0xB0, 0, 0, 0, 0, 0 };

	bmt_reset();
	bmt_privacy_fixture(1);
	bmt_adp.reslist.count = 0;
	ATF_REQUIRE_EQ(1, blued_reslist_add(&bmt_adp.reslist, addr,
	    BDADDR_LE_RANDOM));

	memset(&shadow, 0, sizeof(shadow));
	shadow = bmt_adp.reslist;
	ATF_CHECK_EQ(0, blued_privacy_program(bmt_adp.hci_fd, false, &shadow));
	ATF_CHECK_MSG(!bmt_adp.random_addr_valid,
	    "the local random address must be invalidated with privacy off");
	ATF_CHECK_EQ_MSG(1, shadow.count,
	    "turning local privacy off must not clear the peer identities");
	ATF_CHECK_MSG(!bmt_saw(NG_HCI_OPCODE(NG_HCI_OGF_LE,
	    NG_HCI_OCF_LE_CLEAR_RESOLVING_LIST)),
	    "the resolving list must not be cleared by a privacy-off request");

	bmt_privacy_teardown();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, quarantine_renames_unusable_db_aside);
	ATF_TP_ADD_TC(tp, quarantine_keeps_the_rejected_database);
	ATF_TP_ADD_TC(tp, quarantine_continues_with_an_empty_database);
	ATF_TP_ADD_TC(tp, quarantine_logs_at_security_level);
	ATF_TP_ADD_TC(tp, quarantine_leaves_a_good_database_untouched);
	ATF_TP_ADD_TC(tp, quarantine_fails_closed_without_a_directory_fd);

	ATF_TP_ADD_TC(tp, persist_restore_rejects_out_of_range_io_capability);
	ATF_TP_ADD_TC(tp, persist_restore_accepts_every_valid_io_capability);
	ATF_TP_ADD_TC(tp, persist_restore_range_gates_every_field);
	ATF_TP_ADD_TC(tp, persist_restore_reinstates_discoverable_and_mtu);
	ATF_TP_ADD_TC(tp, persist_restore_ignores_an_empty_name);
	ATF_TP_ADD_TC(tp, persist_settings_round_trip);

	ATF_TP_ADD_TC(tp, reload_reapplies_saved_cli_overrides);
	ATF_TP_ADD_TC(tp, reload_follows_a_replaced_config_inode);
	ATF_TP_ADD_TC(tp, reload_falls_back_to_the_cached_descriptor);
	ATF_TP_ADD_TC(tp, reload_keeps_settings_when_the_file_will_not_parse);
	ATF_TP_ADD_TC(tp, reload_overlay_adopts_persist_owned_live_values);
	ATF_TP_ADD_TC(tp, reload_pushes_reconnect_policy_onto_live_connections);

	ATF_TP_ADD_TC(tp, privacy_program_respects_controller_capacity);
	ATF_TP_ADD_TC(tp, privacy_program_clamps_to_the_host_shadow);
	ATF_TP_ADD_TC(tp, privacy_program_skips_an_unsupported_privacy_mode);
	ATF_TP_ADD_TC(tp, privacy_program_rolls_back_a_half_programmed_entry);
	ATF_TP_ADD_TC(tp, privacy_program_reprograms_runtime_resolv_entries);
	ATF_TP_ADD_TC(tp, privacy_set_restores_the_previous_policy_on_failure);
	ATF_TP_ADD_TC(tp, privacy_set_rejects_an_unknown_descriptor);
	ATF_TP_ADD_TC(tp, privacy_off_keeps_resolution_for_peer_identities);

	return (atf_no_error());
}
