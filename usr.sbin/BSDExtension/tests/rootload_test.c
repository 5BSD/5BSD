/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Root loads (system.SystemExtension.RootLoad, rootload.c, kerneldir.c).  A
 * fixture boot directory (kernel/, modules/), module files with real module
 * metadata (rlmodule.c) and a real sqlite package database in pkg's schema
 * stand in for /boot and /var/db/pkg.  The kernel linker calls are replaced
 * by a small fake kernel (sysext_test_kld_*) that resolves MODULE_DEPEND as
 * the real linker does: a dependency no loaded file provides is searched for
 * in its module path (kernel/, then modules/) and loaded, initialisation
 * included, before the file that needs it -- so a broker that let the kernel
 * resolve dependencies would show here.  Nothing is loaded into the running
 * kernel and nothing needs privilege.  Which callers reach the endpoint at
 * all (UID 0, not jailed, no software authority) is switchboard's decision
 * and is tested there (boot_authority_test root_load_admits).
 */

#include <sys/param.h>
#include <sys/elf.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pthread_np.h>
#include <gelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <kldelf.h>
#include <sqlite3.h>
#include <channel.h>
#include <libservice.h>
#include <extensioncmp.h>

#include "sysext_proto.h"
#include "bsdextension.h"
#include "test_policy.h"

#define	FIXTURE_BUILD_ID	"5bd0c0ffee0123456789abcdef0123456789abcd"

/* --------------------------------------------------------- fake kernel */

#define	FAKE_FILES	16
#define	FAKE_MODS	8
static struct fake_file {
	int	id;
	int	parent;		/* loaded implicitly for this file id */
	char	name[64];
	char	path[MAXPATHLEN];
	unsigned nmods;
	struct {
		char	name[32];
		int	version;
	} mods[FAKE_MODS];
} fake[FAKE_FILES];
static int fake_next_id = 2, fake_loads, fake_unloads, fake_implicit;
/* Every file the fake kernel ever initialised, in order (" a b c "). */
static char fake_history[1024];
/* Loaded behind the broker's back with the next load, or "". */
static char fake_extra[MAXPATHLEN];
/* kldstat(2) fails for file ids from this one on (0: never). */
static int fake_stat_fails_from;
/* Run during the next load (a file changed while the kernel reads it). */
static void (*fake_during_load)(void);
/* kldunload(2) of this file id succeeds but keeps it (it is referenced). */
static int fake_unload_keeps;
/* The fake kernel's module path: what kern.module_path would hold. */
static const char *const fake_module_path[] = { "/boot/kernel",
    "/boot/modules" };

/*
 * /boot/... in the fake kernel is the fixture /boot, looked up by name from the
 * fixture root, as the kernel looks it up from "/": ../boot from the working
 * directory, which is the fixture /boot (and stays the old directory when the
 * fixture /boot is renamed).
 */
static const char *
fake_local(const char *path)
{
	static char local[MAXPATHLEN];

	if (strncmp(path, "/boot/", 6) != 0)
		return (path);
	(void)snprintf(local, sizeof(local), "..%s", path);
	return (local);
}

/* The module metadata of a fixture file, read here with libkldelf. */
static int
fake_metadata(const char *path, struct fake_file *f, char deps[][32],
    int depmin[], int depmax[], unsigned *ndeps)
{
	struct Gmod_metadata md;
	struct Gmod_depend dep;
	struct Gmod_version ver;
	struct elf_file ef;
	GElf_Addr *set;
	long count;
	char name[32];

	*ndeps = 0;
	(void)elf_version(EV_CURRENT);
	if (elf_open_file(&ef, fake_local(path), 0) != 0)
		return (ENOEXEC);
	if (elf_read_linker_set(&ef, MDT_SETNAME, &set, &count) != 0) {
		elf_close_file(&ef);
		return (0);
	}
	for (long i = 0; i < count; i++) {
		if (elf_read_mod_metadata(&ef, set[i], &md) != 0 ||
		    elf_read_string(&ef, md.md_cval, name, sizeof(name)) != 0)
			continue;
		if (md.md_type == MDT_VERSION && f->nmods < FAKE_MODS &&
		    elf_read_mod_version(&ef, md.md_data, &ver) == 0) {
			strlcpy(f->mods[f->nmods].name, name,
			    sizeof(f->mods[0].name));
			f->mods[f->nmods++].version = ver.mv_version;
		} else if (md.md_type == MDT_DEPEND && *ndeps < FAKE_MODS &&
		    elf_read_mod_depend(&ef, md.md_data, &dep) == 0) {
			strlcpy(deps[*ndeps], name, 32);
			depmin[*ndeps] = dep.md_ver_minimum;
			depmax[(*ndeps)++] = dep.md_ver_maximum;
		}
	}
	free(set);
	elf_close_file(&ef);
	return (0);
}

/* modlist_lookup2(): a loaded file provides name within [min, max]. */
static bool
fake_provided(const char *name, int min, int max)
{

	for (size_t i = 0; i < nitems(fake); i++)
		for (unsigned j = 0; fake[i].id != 0 && j < fake[i].nmods; j++)
			if (strcmp(fake[i].mods[j].name, name) == 0 &&
			    fake[i].mods[j].version >= min &&
			    fake[i].mods[j].version <= max)
				return (true);
	return (false);
}

static int fake_unload(int);

/*
 * linker_load_file() + linker_load_dependencies(): load path, first every
 * dependency nothing loaded provides, found by name in the module path.
 */
static int
fake_load_file(const char *path, int parent, int *fileid)
{
	struct fake_file *f = NULL;
	char deps[FAKE_MODS][32], dpath[MAXPATHLEN];
	int depmin[FAKE_MODS], depmax[FAKE_MODS], id, depid, error;
	const char *base = strrchr(path, '/');
	unsigned ndeps;
	bool self;

	base = base != NULL ? base + 1 : path;
	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id != 0 && strcmp(fake[i].name, base) == 0)
			return (EEXIST);
	for (size_t i = 0; i < nitems(fake) && f == NULL; i++)
		if (fake[i].id == 0)
			f = &fake[i];
	if (f == NULL)
		return (ENOMEM);
	memset(f, 0, sizeof(*f));
	if ((error = fake_metadata(path, f, deps, depmin, depmax,
	    &ndeps)) != 0)
		return (error);
	f->id = id = fake_next_id++;
	f->parent = parent;
	strlcpy(f->name, base, sizeof(f->name));
	strlcpy(f->path, path, sizeof(f->path));
	for (unsigned d = 0; d < ndeps; d++) {
		struct stat st;
		bool found = false;

		self = false;
		for (unsigned m = 0; m < f->nmods; m++)
			self |= strcmp(f->mods[m].name, deps[d]) == 0;
		if (self || fake_provided(deps[d], depmin[d], depmax[d]))
			continue;
		for (size_t p = 0; p < nitems(fake_module_path) && !found;
		    p++) {
			snprintf(dpath, sizeof(dpath), "%s/%s.ko",
			    fake_module_path[p], deps[d]);
			found = stat(fake_local(dpath), &st) == 0;
		}
		if (!found || fake_load_file(dpath, id, &depid) != 0 ||
		    !fake_provided(deps[d], depmin[d], depmax[d])) {
			(void)fake_unload(id);
			return (ENOENT);
		}
		fake_implicit++;
		/* The pointer may have moved with the table: look again. */
		for (size_t i = 0; i < nitems(fake); i++)
			if (fake[i].id == id)
				f = &fake[i];
	}
	strlcat(fake_history, base, sizeof(fake_history));
	strlcat(fake_history, " ", sizeof(fake_history));
	*fileid = id;
	return (0);
}

static int
fake_load(const char *path, int *fileid)
{
	int error, extra;

	fake_loads++;
	if (fake_during_load != NULL) {
		fake_during_load();
		fake_during_load = NULL;
	}
	error = fake_load_file(path, 0, fileid);
	if (error == 0 && fake_extra[0] != '\0') {
		(void)fake_load_file(fake_extra, *fileid, &extra);
		fake_extra[0] = '\0';
	}
	return (error);
}

static int
fake_unload(int fileid)
{

	fake_unloads++;
	if (fileid == fake_unload_keeps)
		return (0);
	for (size_t i = 0; i < nitems(fake); i++) {
		if (fake[i].id != fileid)
			continue;
		memset(&fake[i], 0, sizeof(fake[i]));
		/* The linker releases what the file pulled in itself. */
		for (size_t j = 0; j < nitems(fake); j++)
			if (fake[j].id != 0 && fake[j].parent == fileid)
				(void)fake_unload(fake[j].id);
		return (0);
	}
	return (ENOENT);
}

static int
fake_stat(int fileid, char *name, size_t namelen, char *path, size_t pathlen)
{

	if (fake_stat_fails_from != 0 && fileid >= fake_stat_fails_from)
		return (EIO);
	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id == fileid) {
			strlcpy(name, fake[i].name, namelen);
			strlcpy(path, fake[i].path, pathlen);
			return (0);
		}
	return (ENOENT);
}

static int
fake_next(int fileid)
{
	int best = 0;

	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id > fileid && (best == 0 || fake[i].id < best))
			best = fake[i].id;
	return (best);
}

/* modfind(2): module names, not the kernel's bare version records. */
static int
fake_mod_find(const char *name)
{

	for (size_t i = 1; i < nitems(fake); i++)
		for (unsigned j = 0; fake[i].id != 0 && j < fake[i].nmods; j++)
			if (strcmp(fake[i].mods[j].name, name) == 0)
				return (0);
	return (ENOENT);
}

static bool
fake_loaded(const char *name)
{

	for (size_t i = 0; i < nitems(fake); i++)
		if (fake[i].id != 0 && strcmp(fake[i].name, name) == 0)
			return (true);
	return (false);
}

/* The file was initialised at some point (its SYSINITs ran). */
static bool
fake_ever(const char *name)
{
	char word[80];

	snprintf(word, sizeof(word), " %s ", name);
	return (strstr(fake_history, word) != NULL);
}

static void
fake_reset(const char *bootpath)
{

	memset(fake, 0, sizeof(fake));
	fake_next_id = 2;
	fake_loads = fake_unloads = fake_implicit = 0;
	strlcpy(fake_history, " ", sizeof(fake_history));
	fake_extra[0] = '\0';
	fake_stat_fails_from = 0;
	fake_during_load = NULL;
	fake_unload_keeps = 0;
	/* The kernel itself is file id 1, as in the real linker. */
	fake[0].id = 1;
	strlcpy(fake[0].name, "kernel", sizeof(fake[0].name));
	strlcpy(fake[0].path, bootpath, sizeof(fake[0].path));
	strlcpy(fake[0].mods[0].name, "kernel", sizeof(fake[0].mods[0].name));
	fake[0].mods[0].version = 1;
	fake[0].nmods = 1;
	sysext_test_kld_load = fake_load;
	sysext_test_kld_unload = fake_unload;
	sysext_test_kld_stat = fake_stat;
	sysext_test_kld_next = fake_next;
	sysext_test_mod_find = fake_mod_find;
	sysext_test_build_id = FIXTURE_BUILD_ID;
	sysext_test_root_reset();
	sysext_test_decisions_reset();
}

/* ------------------------------------------------------------ fixtures */

static void
write_file(const char *path, const char *content)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	ATF_REQUIRE_MSG(fd >= 0, "%s: %s", path, strerror(errno));
	ATF_REQUIRE((size_t)write(fd, content, strlen(content)) ==
	    strlen(content));
	close(fd);
}

static void
copy_file(const char *from, const char *to)
{
	char buf[8192];
	ssize_t n;
	int in, out;

	in = open(from, O_RDONLY);
	ATF_REQUIRE_MSG(in >= 0, "%s: %s", from, strerror(errno));
	out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE_MSG(out >= 0, "%s: %s", to, strerror(errno));
	while ((n = read(in, buf, sizeof(buf))) > 0)
		ATF_REQUIRE_EQ(n, write(out, buf, (size_t)n));
	close(in);
	close(out);
}

/* Append one byte: the file no longer matches its package record. */
static void
tamper(const char *path)
{
	int fd = open(path, O_WRONLY | O_APPEND);

	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(1, write(fd, "", 1));
	close(fd);
}

static void
checksum_file(const char *path, char *out, size_t outlen)
{
	int fd;

	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, sysext_pkg_checksum_fd(fd, out, outlen));
	close(fd);
}

static void
checksum_of(const char *content, char *out, size_t outlen)
{

	write_file("checksum.tmp", content);
	checksum_file("checksum.tmp", out, outlen);
	unlink("checksum.tmp");
}

/*
 * A minimal native ELF executable whose PT_NOTE carries a GNU build-id: the
 * fixture kernel file (kerneldir.c compares it with kern.build_id).
 */
static void
write_kernel(const char *path, const char *build_id)
{
	struct {
		Elf_Ehdr eh;
		Elf_Phdr ph;
		Elf_Note nh;
		char name[4];
		unsigned char desc[20];
	} image;
	unsigned int byte;
	int fd;

	memset(&image, 0, sizeof(image));
	memcpy(image.eh.e_ident, ELFMAG, SELFMAG);
	image.eh.e_ident[EI_CLASS] = ELF_TARG_CLASS;
	image.eh.e_ident[EI_DATA] = ELF_TARG_DATA;
	image.eh.e_ident[EI_VERSION] = EV_CURRENT;
	image.eh.e_type = ET_EXEC;
	image.eh.e_machine = ELF_TARG_MACH;
	image.eh.e_version = EV_CURRENT;
	image.eh.e_ehsize = sizeof(image.eh);
	image.eh.e_phoff = offsetof(__typeof(image), ph);
	image.eh.e_phentsize = sizeof(image.ph);
	image.eh.e_phnum = 1;
	image.ph.p_type = PT_NOTE;
	image.ph.p_offset = offsetof(__typeof(image), nh);
	image.ph.p_filesz = sizeof(image.nh) + sizeof(image.name) +
	    sizeof(image.desc);
	image.nh.n_namesz = 4;
	image.nh.n_descsz = sizeof(image.desc);
	image.nh.n_type = NT_GNU_BUILD_ID;
	memcpy(image.name, "GNU", 4);
	ATF_REQUIRE_EQ(40, strlen(build_id));
	for (size_t i = 0; i < sizeof(image.desc); i++) {
		ATF_REQUIRE_EQ(1, sscanf(build_id + 2 * i, "%2x", &byte));
		image.desc[i] = (unsigned char)byte;
	}
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)sizeof(image), write(fd, &image,
	    sizeof(image)));
	close(fd);
}

static void
sql(sqlite3 *db, const char *statement)
{
	char *message = NULL;

	ATF_REQUIRE_MSG(sqlite3_exec(db, statement, NULL, NULL, &message) ==
	    SQLITE_OK, "%s: %s", statement, message != NULL ? message : "?");
}

static void
add_file(sqlite3 *db, const char *path, const char *checksum, int package)
{
	char *statement;

	statement = sqlite3_mprintf("INSERT INTO files (path, sha256, uname, "
	    "gname, perm, fflags, mtime, symlink_target, package_id) VALUES "
	    "(%Q, %Q, 'root', 'wheel', 365, 0, 0, NULL, %d);", path, checksum,
	    package);
	sql(db, statement);
	sqlite3_free(statement);
}

/* Record kernel/<file> as installed by package with its current checksum. */
static void
add_installed(sqlite3 *db, const char *file, int package)
{
	char local[MAXPATHLEN], path[MAXPATHLEN];
	char sum[SYSEXT_PKG_CHECKSUM_MAX];

	snprintf(local, sizeof(local), "kernel/%s", file);
	snprintf(path, sizeof(path), "/boot/kernel/%s", file);
	checksum_file(local, sum, sizeof(sum));
	add_file(db, path, sum, package);
}

static void
pkg_schema(sqlite3 *db)
{

	sql(db, "CREATE TABLE packages (id INTEGER PRIMARY KEY, origin TEXT "
	    "NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL);"
	    "CREATE TABLE files (path TEXT PRIMARY KEY, sha256 TEXT, uname "
	    "TEXT, gname TEXT, perm INTEGER, fflags INTEGER, mtime INTEGER, "
	    "symlink_target TEXT, package_id INTEGER REFERENCES packages(id));"
	    "CREATE TABLE annotation (annotation_id INTEGER PRIMARY KEY, "
	    "annotation TEXT NOT NULL UNIQUE);"
	    "CREATE TABLE pkg_annotation (package_id INTEGER, tag_id INTEGER "
	    "NOT NULL, value_id INTEGER NOT NULL, UNIQUE (package_id, tag_id));"
	    "INSERT INTO packages VALUES (1, 'base/5BSD-kernel-generic', "
	    "'5BSD-kernel-generic', '16.snap1');"
	    "INSERT INTO packages VALUES (2, 'sysutils/evil-kmod', 'evil-kmod', "
	    "'1.0');"
	    "INSERT INTO packages VALUES (3, 'base/5BSD-other', '5BSD-other', "
	    "'16.snap1');"
	    "INSERT INTO annotation VALUES (1, 'repository'), (2, '5BSD-base'), "
	    "(3, 'FreeBSD-base'), (4, 'set'), (5, 'kernels');"
	    "INSERT INTO pkg_annotation VALUES (1, 1, 2), (1, 4, 5), (2, 1, 2), "
	    "(3, 1, 3);");
}

/*
 * The fixture root (root/, the kernel's "/") and its boot/, the fixture /boot
 * and the test's working directory from here on, with pkg/local.sqlite:
 *   kernel/kernel      the running kernel (build-id FIXTURE_BUILD_ID)
 *   rltest_a.ko        base package, 5BSD-base, matching checksum
 *   rltest_b.ko        on disk, recorded by no package
 *   rltest_t.ko        base package, modified since it was recorded
 *   rltest_p.ko        recorded by a ports package (origin sysutils/...)
 *   rltest_r.ko        base origin, installed from another repository
 *   rltest_l.ko        a symbolic link to rltest_a.ko
 *   rltest_d.ko        base package, needs "rldep" (only in modules/)
 *   rltest_n.ko        base package, needs "rlbase" 1 (rlbase.ko, base)
 *   rltest_v.ko        base package, needs "rlbase" 2 (none provides it)
 *   rltest_x.ko        base package, needs "mac_rltest" (base, protected)
 *   rltest_k.ko        base package, needs "kernel" and "rlbase"
 *   modules/rldep.ko   outside the kernel directory, recorded by no package
 *   modules/rltest_m.ko outside the kernel directory
 *   modules/rlother.ko outside the kernel directory, also provides "rlbase" 2
 */
static void
fixture_files(const atf_tc_t *tc)
{
	/* Installed by a package: { file, fixture it is a copy of, package }. */
	static const struct { const char *file, *from; int package; } base[] = {
		{ "rltest_a.ko", "rltest_a.ko", 1 },
		{ "rltest_p.ko", "rltest_a.ko", 2 },
		{ "rltest_r.ko", "rltest_a.ko", 3 },
		{ "rltest_t.ko", "rltest_a.ko", 1 },
		{ "rltest_d.ko", "rltest_d.ko", 1 },
		{ "rltest_n.ko", "rltest_n.ko", 1 },
		{ "rltest_v.ko", "rltest_v.ko", 1 },
		{ "rltest_x.ko", "rltest_x.ko", 1 },
		{ "rltest_k.ko", "rltest_k.ko", 1 },
		{ "rlbase.ko", "rlbase.ko", 1 },
		{ "mac_rltest.ko", "mac_rltest.ko", 1 },
	};
	char from[MAXPATHLEN], to[MAXPATHLEN], srcdir[MAXPATHLEN];
	sqlite3 *db;

	ATF_REQUIRE(realpath(atf_tc_get_config_var(tc, "srcdir"), srcdir) !=
	    NULL);
	ATF_REQUIRE_EQ(0, mkdir("root", 0755));
	ATF_REQUIRE_EQ(0, mkdir("root/boot", 0755));
	ATF_REQUIRE_EQ(0, chdir("root/boot"));
	ATF_REQUIRE_EQ(0, mkdir("kernel", 0755));
	ATF_REQUIRE_EQ(0, mkdir("modules", 0755));
	ATF_REQUIRE_EQ(0, mkdir("pkg", 0755));
	write_kernel("kernel/kernel", FIXTURE_BUILD_ID);
	for (size_t i = 0; i < nitems(base); i++) {
		snprintf(from, sizeof(from), "%s/%s", srcdir, base[i].from);
		snprintf(to, sizeof(to), "kernel/%s", base[i].file);
		copy_file(from, to);
	}
	copy_file("kernel/rltest_a.ko", "kernel/rltest_b.ko");
	snprintf(from, sizeof(from), "%s/rldep.ko", srcdir);
	copy_file(from, "modules/rldep.ko");
	copy_file("kernel/rltest_a.ko", "modules/rltest_m.ko");
	snprintf(from, sizeof(from), "%s/rlother.ko", srcdir);
	copy_file(from, "modules/rlother.ko");
	ATF_REQUIRE_EQ(0, symlink("rltest_a.ko", "kernel/rltest_l.ko"));

	ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_open("pkg/local.sqlite", &db));
	sql(db, "PRAGMA journal_mode = DELETE;");
	pkg_schema(db);
	for (size_t i = 0; i < nitems(base); i++)
		add_installed(db, base[i].file, base[i].package);
	add_installed(db, "rltest_l.ko", 1);
	ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_close(db));
	tamper("kernel/rltest_t.ko");
}

static void
fixture_remove(void)
{

	ATF_REQUIRE_EQ(0, chdir("../.."));
	ATF_REQUIRE_EQ(0, system("rm -rf root"));
}

/* "/" (fstatat(2) only, as the broker holds it) and /boot for kerneldir.c. */
static void
fixture_root_boot(void)
{

	sysext_root_dirfd = open("..", O_DIRECTORY | O_RDONLY);
	sysext_boot_dirfd = open(".", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(sysext_root_dirfd >= 0 && sysext_boot_dirfd >= 0);
	ATF_REQUIRE_EQ(0, sysext_root_dir_limit(sysext_root_dirfd));
}

/* Point rootload.c at the fixture directories in this process. */
static void
fixture_dirs(const atf_tc_t *tc)
{

	fixture_files(tc);
	fake_reset("/boot/kernel/kernel");
	fixture_root_boot();
	sysext_pkgdb_dirfd = open("pkg", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(sysext_pkgdb_dirfd >= 0);
	ATF_REQUIRE_EQ(0, sysext_kernel_dir_open());
	ATF_REQUIRE_STREQ("/boot/kernel", sysext_kernel_dir);
}

static uint32_t
load_detail(const char *name, int *errorp, char *detail, size_t detaillen)
{
	uint32_t result;

	result = sysext_root_load("5BSD-base", name, errorp, detail,
	    detaillen);
	printf("load %s -> %u: %s\n", name, result, detail);
	return (result);
}

static uint32_t
load(const char *name, int *errorp)
{
	char detail[512];

	return (load_detail(name, errorp, detail, sizeof(detail)));
}

static void
channel_pair(int *client, int *provider)
{
	int pair[2];

	if (mac_capability_channel_create(pair) == -1) {
		if (errno == ENOSYS)
			atf_tc_skip("capability channel syscall unavailable");
		atf_tc_fail("channel creation: %s", strerror(errno));
	}
	*client = pair[0];
	*provider = pair[1];
}

static void
policy(struct sysext_config *cfg, const char *repository)
{

	test_base_policy(cfg);
	if (repository != NULL)
		strlcpy(cfg->root_load_repository, repository,
		    sizeof(cfg->root_load_repository));
}

/* ------------------------------------------------------------- checksum */

/*
 * pkg 2.8.4 recorded this checksum for /usr/share/misc/init.ee (25 bytes) in
 * a 5BSD installation's local.sqlite: "2$" and pkg's z-base-32 of BLAKE2b-512.
 */
ATF_TC_WITHOUT_HEAD(checksum_matches_pkg);
ATF_TC_BODY(checksum_matches_pkg, tc)
{
	char sum[SYSEXT_PKG_CHECKSUM_MAX], small[8];
	int fd;

	(void)tc;
	checksum_of("emacs\nnoexpand\nnomargins\n", sum, sizeof(sum));
	ATF_CHECK_STREQ("2$po7r6okjgx8rh4399j9ofwwxcogck8h1ey3rjkcfr1xk5gr1so"
	    "jxc8ms5stpgkx1cqcu16y3kxo1r3e3yhgy1ha5y54wwbptwjy9rpd", sum);
	write_file("x", "x");
	fd = open("x", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK_EQ(ENAMETOOLONG, sysext_pkg_checksum_fd(fd, small,
	    sizeof(small)));
	close(fd);
}

/* ----------------------------------------------------- package database */

ATF_TC_WITHOUT_HEAD(pkgdb_lookup);
ATF_TC_BODY(pkgdb_lookup, tc)
{
	struct sysext_pkg_record rec;
	int dir;

	fixture_files(tc);
	dir = open("pkg", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dir >= 0);
	ATF_REQUIRE_EQ(0, sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_a.ko",
	    &rec));
	ATF_CHECK(rec.found);
	ATF_CHECK_STREQ("5BSD-kernel-generic", rec.package);
	ATF_CHECK_STREQ("base/5BSD-kernel-generic", rec.origin);
	ATF_CHECK_STREQ("5BSD-base", rec.repository);
	ATF_CHECK(strncmp(rec.checksum, "2$", 2) == 0);
	ATF_CHECK(!rec.symlink);
	ATF_CHECK_EQ(0, sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_b.ko",
	    &rec));
	ATF_CHECK(!rec.found);
	ATF_REQUIRE_EQ(0, unlink("pkg/local.sqlite"));
	ATF_CHECK_EQ(ENOENT, sysext_pkgdb_lookup(dir,
	    "/boot/kernel/rltest_a.ko", &rec));
	close(dir);
}

/* Build pkg/hostile.sqlite with extra statements after the base schema. */
static void
hostile_db(const char *journal, const char *extra)
{
	char sum[SYSEXT_PKG_CHECKSUM_MAX], *statement;
	sqlite3 *db;

	(void)unlink("pkg/local.sqlite");
	(void)unlink("pkg/local.sqlite-wal");
	(void)unlink("pkg/local.sqlite-shm");
	ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_open("pkg/local.sqlite", &db));
	statement = sqlite3_mprintf("PRAGMA journal_mode = %s;", journal);
	sql(db, statement);
	sqlite3_free(statement);
	pkg_schema(db);
	checksum_of("module a\n", sum, sizeof(sum));
	add_file(db, "/boot/kernel/rltest_a.ko", sum, 1);
	if (extra != NULL)
		sql(db, extra);
	ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_close(db));
}

static int
truncate_db(off_t size)
{

	return (truncate("pkg/local.sqlite", size));
}

/*
 * A hostile or damaged database fails closed in the child and never makes a
 * file qualify: a write-ahead-log header, a schema of views and triggers, a
 * truncated file, garbage, a row larger than the reply.
 */
ATF_TC_WITHOUT_HEAD(pkgdb_hostile);
ATF_TC_BODY(pkgdb_hostile, tc)
{
	struct sysext_pkg_record rec;
	char big[4096];
	int dir;

	fixture_files(tc);
	dir = open("pkg", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE(dir >= 0);

	/* WAL mode, checkpointed: read as a rollback-journal image. */
	hostile_db("WAL", NULL);
	ATF_CHECK_EQ(0, sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_a.ko",
	    &rec));
	ATF_CHECK(rec.found);
	/* Rows only in an uncheckpointed WAL are not seen. */
	{
		char sum[SYSEXT_PKG_CHECKSUM_MAX];
		sqlite3 *db;

		ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_open("pkg/local.sqlite",
		    &db));
		ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_db_config(db,
		    SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, NULL));
		sql(db, "PRAGMA wal_autocheckpoint = 0;");
		checksum_of("module b\n", sum, sizeof(sum));
		add_file(db, "/boot/kernel/rltest_b.ko", sum, 1);
		ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_close(db));
	}
	ATF_REQUIRE_EQ(0, access("pkg/local.sqlite-wal", F_OK));
	ATF_CHECK_EQ(0, sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_b.ko",
	    &rec));
	ATF_CHECK(!rec.found);

	/* "files" is a view: views are disabled, the query fails. */
	hostile_db("DELETE", "ALTER TABLE files RENAME TO real_files;"
	    "CREATE VIEW files AS SELECT * FROM real_files;");
	ATF_CHECK(sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_a.ko",
	    &rec) != 0);
	/* A trigger in the schema does not run, and the read still works. */
	hostile_db("DELETE", "CREATE TABLE seen (x); CREATE TRIGGER t AFTER "
	    "INSERT ON annotation BEGIN INSERT INTO seen VALUES (1); END;");
	ATF_CHECK_EQ(0, sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_a.ko",
	    &rec));
	ATF_CHECK(rec.found);

	/* A row larger than the fixed reply: refused, never truncated. */
	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	hostile_db("DELETE", NULL);
	{
		char *statement;
		sqlite3 *db;

		ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_open("pkg/local.sqlite",
		    &db));
		statement = sqlite3_mprintf("UPDATE packages SET name = %Q "
		    "WHERE id = 1;", big);
		sql(db, statement);
		sqlite3_free(statement);
		ATF_REQUIRE_EQ(SQLITE_OK, sqlite3_close(db));
	}
	ATF_CHECK_EQ(EINVAL, sysext_pkgdb_lookup(dir,
	    "/boot/kernel/rltest_a.ko", &rec));
	ATF_CHECK(!rec.found);

	/* Truncated: below a page, then mid-file. */
	hostile_db("DELETE", NULL);
	ATF_REQUIRE_EQ(0, truncate_db(100));
	ATF_CHECK_EQ(EFTYPE, sysext_pkgdb_lookup(dir,
	    "/boot/kernel/rltest_a.ko", &rec));
	hostile_db("DELETE", NULL);
	ATF_REQUIRE_EQ(0, truncate_db(4096 + 17));
	ATF_CHECK(sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_a.ko",
	    &rec) != 0 || !rec.found);

	/* Garbage of a plausible size. */
	memset(big, 0x5a, sizeof(big));
	{
		int fd = open("pkg/local.sqlite", O_WRONLY | O_TRUNC);

		ATF_REQUIRE(fd >= 0);
		ATF_REQUIRE_EQ((ssize_t)sizeof(big), write(fd, big,
		    sizeof(big)));
		close(fd);
	}
	ATF_CHECK(sysext_pkgdb_lookup(dir, "/boot/kernel/rltest_a.ko",
	    &rec) != 0);
	ATF_CHECK(!rec.found);

	/* Not a regular file: refused before it is opened (no blocking). */
	ATF_REQUIRE_EQ(0, unlink("pkg/local.sqlite"));
	ATF_REQUIRE_EQ(0, mkfifo("pkg/local.sqlite", 0644));
	ATF_CHECK_EQ(EFTYPE, sysext_pkgdb_lookup(dir,
	    "/boot/kernel/rltest_a.ko", &rec));
	close(dir);
}

/* ------------------------------------------------------------ decisions */

ATF_TC_WITHOUT_HEAD(load_package_module);
ATF_TC_BODY(load_package_module, tc)
{
	char detail[256];
	int error;

	fixture_dirs(tc);
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_a", &error));
	ATF_CHECK_EQ(0, error);
	ATF_CHECK(fake_loaded("rltest_a.ko"));
	/* By the absolute path, so kern.module_path cannot redirect it. */
	for (size_t i = 0; i < nitems(fake); i++)
		if (strcmp(fake[i].name, "rltest_a.ko") == 0)
			ATF_CHECK_STREQ("/boot/kernel/rltest_a.ko", fake[i].path);
	/* The kernel reports a second load as present. */
	ATF_CHECK_EQ(SYSEXT_DECISION_PRESENT, load("rltest_a.ko", &error));
	/* Unload: only what a root load loaded, once. */
	ATF_CHECK_EQ(SYSEXT_DECISION_UNLOADED, sysext_root_unload("rltest_a",
	    &error, detail, sizeof(detail)));
	ATF_CHECK(!fake_loaded("rltest_a.ko"));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_ROOT_LOADED,
	    sysext_root_unload("rltest_a", &error, detail, sizeof(detail)));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_ROOT_LOADED,
	    sysext_root_unload("rltest_d", &error, detail, sizeof(detail)));
	/* Another client relying on it blocks a root unload. */
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_a", &error));
	sysext_root_note_shared("rltest_a");
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_ROOT_LOADED,
	    sysext_root_unload("rltest_a", &error, detail, sizeof(detail)));
	ATF_CHECK(fake_loaded("rltest_a.ko"));
}

/*
 * M3: the modules a root unload refuses are refused for loading as well, by
 * the same list: here a base-package file that passes every other check.
 */
ATF_TC_WITHOUT_HEAD(refuse_protected);
ATF_TC_BODY(refuse_protected, tc)
{
	static const char *const names[] = { "mac_portacl", "mac_ntpd.ko",
	    "dtraceall", "dtrace", "dtmalloc", "kinst", "fbt", "sdt",
	    "systrace", "fasttrap", "profile", "prototype", "hypertrace",
	    "hwpmc", "ksyms.ko", "vmm", "zfs", "opensolaris", "pf", "pflog",
	    "pfsync", "pflow", "ipfw", "ipfw_nat", "ipl" };
	/* Exact names: no prefix but the MAC policies'; decided unprotected. */
	static const char *const others[] = { "pfunrelated", "fbtest",
	    "profiler", "vmmfs", "zfstest", "sdtx", "kinstall", "if_mos",
	    "ext2fs", "nullfs", "unionfs", "linux64", "linux_common" };
	char detail[512];
	int error;

	fixture_dirs(tc);
	ATF_CHECK_EQ(SYSEXT_DECISION_PROTECTED, load_detail("mac_rltest",
	    &error, detail, sizeof(detail)));
	ATF_CHECK(strstr(detail, "mac_rltest.ko") != NULL);
	for (size_t i = 0; i < nitems(names); i++) {
		ATF_CHECK_MSG(sysext_root_protected(names[i]), "%s", names[i]);
		ATF_CHECK_EQ_MSG(SYSEXT_DECISION_PROTECTED, load(names[i],
		    &error), "%s", names[i]);
		ATF_CHECK_EQ_MSG(SYSEXT_DECISION_PROTECTED,
		    sysext_root_unload(names[i], &error, detail,
		    sizeof(detail)), "%s", names[i]);
	}
	for (size_t i = 0; i < nitems(others); i++)
		ATF_CHECK_MSG(!sysext_root_protected(others[i]), "%s",
		    others[i]);
	/* A module that needs a protected one is refused with it. */
	ATF_CHECK_EQ(SYSEXT_DECISION_PROTECTED, load("rltest_x", &error));
	ATF_CHECK_EQ(0, fake_loads);
	ATF_CHECK(!fake_ever("mac_rltest.ko"));
}

ATF_TC_WITHOUT_HEAD(refuse_unpackaged_file);
ATF_TC_BODY(refuse_unpackaged_file, tc)
{
	int error;

	fixture_dirs(tc);
	/* A file copied into /boot/kernel that no package records. */
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load("rltest_b", &error));
	/* Owned by a ports package, or by a base package of another repo. */
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load("rltest_p", &error));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load("rltest_r", &error));
	ATF_CHECK_EQ(0, fake_loads);
}

ATF_TC_WITHOUT_HEAD(refuse_tampered_checksum);
ATF_TC_BODY(refuse_tampered_checksum, tc)
{
	int error;

	fixture_dirs(tc);
	ATF_CHECK_EQ(SYSEXT_DECISION_CHECKSUM, load("rltest_t", &error));
	/* A byte added to a module that verified before. */
	tamper("kernel/rltest_a.ko");
	ATF_CHECK_EQ(SYSEXT_DECISION_CHECKSUM, load("rltest_a", &error));
	ATF_CHECK_EQ(0, fake_loads);
}

ATF_TC_WITHOUT_HEAD(refuse_outside_kernel_dir);
ATF_TC_BODY(refuse_outside_kernel_dir, tc)
{
	int error;

	fixture_dirs(tc);
	/* Only in another module directory, absent, or a symbolic link. */
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load("rltest_m", &error));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load("rltest_none",
	    &error));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load("rltest_l", &error));
	/* A FIFO is refused without being opened (an open could block). */
	ATF_REQUIRE_EQ(0, mkfifo("kernel/rltest_f.ko", 0644));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load("rltest_f", &error));
	ATF_CHECK_EQ(0, fake_loads);
}

/*
 * M1: a dependency the kernel would find through its module path (here
 * modules/, as /boot/modules or a directory added to kern.module_path) is
 * refused before anything is loaded: its initialisation never runs.
 */
ATF_TC_WITHOUT_HEAD(dependency_outside_kernel_dir);
ATF_TC_BODY(dependency_outside_kernel_dir, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load_detail("rltest_d",
	    &error, detail, sizeof(detail)));
	ATF_CHECK(strstr(detail, "rldep") != NULL);
	ATF_CHECK_MSG(!fake_ever("rldep.ko"), "initialised: %s", fake_history);
	ATF_CHECK(!fake_ever("rltest_d.ko"));
	ATF_CHECK_EQ(0, fake_loads);
}

/* M1 + S1: a dependency in the kernel directory passes the same checks. */
ATF_TC_WITHOUT_HEAD(dependency_checked_before_load);
ATF_TC_BODY(dependency_checked_before_load, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	/* Planted in the kernel directory, recorded by no package. */
	copy_file("modules/rldep.ko", "kernel/rldep.ko");
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load_detail("rltest_d",
	    &error, detail, sizeof(detail)));
	ATF_CHECK(strstr(detail, "dependency of rltest_d.ko") != NULL);
	/* A base dependency modified since installation. */
	tamper("kernel/rlbase.ko");
	ATF_CHECK_EQ(SYSEXT_DECISION_CHECKSUM, load("rltest_n", &error));
	ATF_CHECK_EQ(0, fake_loads);
	ATF_CHECK_MSG(strcmp(fake_history, " ") == 0, "initialised: %s",
	    fake_history);
}

/*
 * M1: a verified dependency is loaded first, by absolute path, so the
 * kernel resolves nothing itself; the versions must match.
 */
ATF_TC_WITHOUT_HEAD(dependency_loaded_first);
ATF_TC_BODY(dependency_loaded_first, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load_detail("rltest_n", &error,
	    detail, sizeof(detail)));
	ATF_CHECK_STREQ(" rlbase.ko rltest_n.ko ", fake_history);
	ATF_CHECK_EQ(0, fake_implicit);
	ATF_CHECK_EQ(2, fake_loads);
	for (size_t i = 0; i < nitems(fake); i++)
		if (strcmp(fake[i].name, "rlbase.ko") == 0)
			ATF_CHECK_STREQ("/boot/kernel/rlbase.ko", fake[i].path);
	/* Both were root loads: each may be unloaded, the user first. */
	ATF_CHECK_EQ(SYSEXT_DECISION_UNLOADED, sysext_root_unload("rltest_n",
	    &error, detail, sizeof(detail)));
	ATF_CHECK_EQ(SYSEXT_DECISION_UNLOADED, sysext_root_unload("rlbase",
	    &error, detail, sizeof(detail)));
	/* Loaded already: no second copy. */
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rlbase", &error));
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_n", &error));
	ATF_CHECK_EQ(4, fake_loads);
	/* The kernel's own interfaces are not files to load. */
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_k", &error));
	ATF_CHECK_EQ(0, fake_implicit);
}

ATF_TC_WITHOUT_HEAD(dependency_version_mismatch);
ATF_TC_BODY(dependency_version_mismatch, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	ATF_CHECK_EQ(SYSEXT_DECISION_FAILED, load_detail("rltest_v", &error,
	    detail, sizeof(detail)));
	ATF_CHECK(strstr(detail, "version 2-2") != NULL);
	ATF_CHECK_EQ(0, fake_loads);
}

/*
 * M1: should the kernel still load a file nobody checked (a loaded module of
 * another version sends it searching), everything this request loaded is
 * unloaded again and the load refused.
 */
ATF_TC_WITHOUT_HEAD(unexpected_file_undone);
ATF_TC_BODY(unexpected_file_undone, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	strlcpy(fake_extra, "/boot/modules/rldep.ko", sizeof(fake_extra));
	ATF_CHECK_EQ(SYSEXT_DECISION_CHANGED, load_detail("rltest_n", &error,
	    detail, sizeof(detail)));
	ATF_CHECK(strstr(detail, "/boot/modules/rldep.ko") != NULL);
	ATF_CHECK(!fake_loaded("rltest_n.ko") && !fake_loaded("rlbase.ko") &&
	    !fake_loaded("rldep.ko"));
}

/* S2: a new file the broker cannot identify fails the load closed. */
ATF_TC_WITHOUT_HEAD(kldstat_failure_refused);
ATF_TC_BODY(kldstat_failure_refused, tc)
{
	int error;

	fixture_dirs(tc);
	fake_stat_fails_from = 2;
	ATF_CHECK_EQ(SYSEXT_DECISION_CHANGED, load("rltest_a", &error));
	ATF_CHECK(!fake_loaded("rltest_a.ko"));
}

/* S3: rewritten during the load with its old mtime restored. */
static void
rewrite_keeping_mtime(void)
{
	struct timespec times[2];
	struct stat st;

	ATF_REQUIRE_EQ(0, stat("kernel/rltest_a.ko", &st));
	copy_file("kernel/rltest_a.ko", "rewrite.tmp");
	copy_file("rewrite.tmp", "kernel/rltest_a.ko");
	times[0] = st.st_atim;
	times[1] = st.st_mtim;
	ATF_REQUIRE_EQ(0, utimensat(AT_FDCWD, "kernel/rltest_a.ko", times, 0));
}

ATF_TC_WITHOUT_HEAD(changed_with_mtime_restored);
ATF_TC_BODY(changed_with_mtime_restored, tc)
{
	int error;

	fixture_dirs(tc);
	/* Let the ctime move on. */
	usleep(20000);
	fake_during_load = rewrite_keeping_mtime;
	ATF_CHECK_EQ(SYSEXT_DECISION_CHANGED, load("rltest_a", &error));
	ATF_CHECK(!fake_loaded("rltest_a.ko"));
}

/*
 * M2: the kernel directory is reopened by name for every load.  Replaced by
 * a directory with another kernel (installkernel before the reboot): refused.
 * With the running kernel: the new directory is used, not the stale handle.
 */
ATF_TC_WITHOUT_HEAD(kernel_dir_replaced);
ATF_TC_BODY(kernel_dir_replaced, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	ATF_REQUIRE_EQ(0, rename("kernel", "kernel.old"));
	ATF_REQUIRE_EQ(0, mkdir("kernel", 0755));
	write_kernel("kernel/kernel", "0000000000000000000000000000000000000001");
	copy_file("kernel.old/rltest_a.ko", "kernel/rltest_a.ko");
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load_detail("rltest_a",
	    &error, detail, sizeof(detail)));
	ATF_CHECK(strstr(detail, "not the running kernel") != NULL);
	ATF_CHECK_EQ(0, fake_loads);

	/* The same kernel in a new directory: adopted, checked there. */
	write_kernel("kernel/kernel", FIXTURE_BUILD_ID);
	tamper("kernel/rltest_a.ko");
	ATF_CHECK_EQ(SYSEXT_DECISION_CHECKSUM, load("rltest_a", &error));
	copy_file("kernel.old/rltest_a.ko", "kernel/rltest_a.ko");
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_a", &error));
	ATF_CHECK_EQ(1, fake_loads);
}

/* M2: a kernel file replaced in place (kernel package upgrade, no reboot). */
ATF_TC_WITHOUT_HEAD(kernel_replaced_in_place);
ATF_TC_BODY(kernel_replaced_in_place, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	write_kernel("kernel/kernel", "0000000000000000000000000000000000000002");
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load_detail("rltest_a",
	    &error, detail, sizeof(detail)));
	ATF_CHECK_EQ(ESTALE, error);
	ATF_CHECK_EQ(0, fake_loads);
}

/* The directory comes from kernel file id 1: a kernel.old boot uses it. */
ATF_TC_WITHOUT_HEAD(kernel_dir_from_boot_path);
ATF_TC_BODY(kernel_dir_from_boot_path, tc)
{
	int error;

	fixture_files(tc);
	ATF_REQUIRE_EQ(0, system("cp -Rp kernel kernel.old"));
	fake_reset("/boot/kernel.old/kernel");
	fixture_root_boot();
	sysext_pkgdb_dirfd = open("pkg", O_DIRECTORY | O_RDONLY);
	ATF_REQUIRE_EQ(0, sysext_kernel_dir_open());
	ATF_CHECK_STREQ("/boot/kernel.old", sysext_kernel_dir);
	/* pkg records /boot/kernel only: nothing in kernel.old qualifies. */
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_PACKAGED, load("rltest_a", &error));
	/* Booted from elsewhere, or another kernel there: no directory. */
	fake_reset("/kernel");
	ATF_CHECK(sysext_kernel_dir_open() != 0);
	fake_reset("/boot/kernel/kernel");
	sysext_test_build_id = "0000000000000000000000000000000000000003";
	ATF_CHECK_EQ(ESTALE, sysext_kernel_dir_open());
}

ATF_TC_WITHOUT_HEAD(refuse_without_database);
ATF_TC_BODY(refuse_without_database, tc)
{
	int error;

	fixture_dirs(tc);
	ATF_REQUIRE_EQ(0, unlink("pkg/local.sqlite"));
	ATF_CHECK_EQ(SYSEXT_DECISION_PKGDB, load("rltest_a", &error));
	ATF_CHECK_EQ(ENOENT, error);
	ATF_CHECK_EQ(0, fake_loads);
}


/* ------------------------------------------------- races and other files */

/* M2: a /boot renamed and replaced by a copy with another module file. */
static void
replace_boot(void)
{

	ATF_REQUIRE_EQ(0, rename("../boot", "../boot.old"));
	ATF_REQUIRE_EQ(0, system("cp -Rp ../boot.old ../boot"));
	tamper("../boot/kernel/rltest_a.ko");
}

/*
 * The kernel resolves /boot/kernel/NAME.ko from "/", not through the /boot
 * the broker holds: a /boot replaced (or mounted over) is refused, before a
 * load and when it happens during one.
 */
ATF_TC_WITHOUT_HEAD(boot_replaced);
ATF_TC_BODY(boot_replaced, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	replace_boot();
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_KERNEL_DIR, load_detail("rltest_a",
	    &error, detail, sizeof(detail)));
	ATF_CHECK(strstr(detail, "replaced or mounted over") != NULL);
	ATF_CHECK_EQ(ESTALE, error);
	ATF_CHECK_EQ(0, fake_loads);
}

ATF_TC_WITHOUT_HEAD(boot_replaced_during_load);
ATF_TC_BODY(boot_replaced_during_load, tc)
{
	int error;

	fixture_dirs(tc);
	fake_during_load = replace_boot;
	ATF_CHECK_EQ(SYSEXT_DECISION_CHANGED, load("rltest_a", &error));
	ATF_CHECK_EQ(1, fake_loads);
	ATF_CHECK(!fake_loaded("rltest_a.ko"));
}

/*
 * A module of the dependency's name loaded from another file (here
 * modules/rlother.ko, "rlbase" version 2): modfind(2) finds it but reports
 * no version, and the kernel, finding it out of range, would search
 * kern.module_path itself.  Refused before anything is loaded.
 */
ATF_TC_WITHOUT_HEAD(dependency_loaded_out_of_range);
ATF_TC_BODY(dependency_loaded_out_of_range, tc)
{
	char detail[512];
	int error, id;

	fixture_dirs(tc);
	ATF_REQUIRE_EQ(0, fake_load_file("/boot/modules/rlother.ko", 0, &id));
	ATF_CHECK_EQ(SYSEXT_DECISION_FAILED, load_detail("rltest_n", &error,
	    detail, sizeof(detail)));
	ATF_CHECK(strstr(detail, "kern.module_path") != NULL);
	ATF_CHECK_EQ(0, fake_loads);
	ATF_CHECK_MSG(!fake_ever("rlbase.ko"), "initialised: %s", fake_history);
	ATF_CHECK(fake_loaded("rlother.ko"));
}

/* Another process loads a file while the request loads its own. */
static void
concurrent_load_a(void)
{
	int id;

	ATF_REQUIRE_EQ(0, fake_load_file("/boot/kernel/rltest_a.ko", 0, &id));
}

static void
concurrent_load_b(void)
{
	int id;

	ATF_REQUIRE_EQ(0, fake_load_file("/boot/kernel/rltest_b.ko", 0, &id));
}

/*
 * Undoing a request unloads only the file ids it loaded: the module loaded
 * by someone else meanwhile (present) and a file another process loaded
 * during the load (refused) stay loaded.
 */
ATF_TC_WITHOUT_HEAD(foreign_load_left_loaded);
ATF_TC_BODY(foreign_load_left_loaded, tc)
{
	int error;

	fixture_dirs(tc);
	fake_during_load = concurrent_load_a;
	ATF_CHECK_EQ(SYSEXT_DECISION_PRESENT, load("rltest_a", &error));
	ATF_CHECK(fake_loaded("rltest_a.ko"));
	fake_during_load = concurrent_load_b;
	ATF_CHECK_EQ(SYSEXT_DECISION_CHANGED, load("rltest_n", &error));
	ATF_CHECK(fake_loaded("rltest_b.ko"));
	ATF_CHECK(!fake_loaded("rlbase.ko") && !fake_loaded("rltest_n.ko"));
}

struct load_thread_arg {
	const char *name;
	uint32_t result;
};

static void *
load_thread(void *arg)
{
	struct load_thread_arg *a = arg;
	int error;

	a->result = load(a->name, &error);
	return (NULL);
}

/*
 * The package database and checksum checks run without sysext_load_lock (a
 * devd driver load does not wait for them), and one database child answers
 * every file of a request.
 */
ATF_TC_WITHOUT_HEAD(checks_outside_load_lock);
ATF_TC_BODY(checks_outside_load_lock, tc)
{
	struct load_thread_arg a = { "rltest_t", 0 };
	struct timespec deadline;
	pthread_t t;
	int error, joined;

	fixture_dirs(tc);
	pthread_mutex_lock(&sysext_load_lock);
	ATF_REQUIRE_EQ(0, pthread_create(&t, NULL, load_thread, &a));
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_REALTIME, &deadline));
	deadline.tv_sec += 5;
	joined = pthread_timedjoin_np(t, NULL, &deadline);
	pthread_mutex_unlock(&sysext_load_lock);
	ATF_CHECK_EQ_MSG(0, joined, "the refusal waited for the load lock");
	if (joined != 0)
		ATF_REQUIRE_EQ(0, pthread_join(t, NULL));
	ATF_CHECK_EQ(SYSEXT_DECISION_CHECKSUM, a.result);
	sysext_test_pkgdb_children = 0;
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, load("rltest_n", &error));
	ATF_CHECK_EQ(2, fake_loads);
	ATF_CHECK_EQ(1, sysext_test_pkgdb_children);
}

/*
 * The kernel keeps a file another loaded file depends on: kldunload(2)
 * succeeds, the file stays.  Reported as still referenced; the slot is kept,
 * so the file can be unloaded once its dependent is gone.
 */
ATF_TC_WITHOUT_HEAD(unload_still_referenced);
ATF_TC_BODY(unload_still_referenced, tc)
{
	char detail[512];
	int error;

	fixture_dirs(tc);
	ATF_REQUIRE_EQ(SYSEXT_DECISION_LOADED, load("rltest_n", &error));
	for (size_t i = 0; i < nitems(fake); i++)
		if (strcmp(fake[i].name, "rlbase.ko") == 0)
			fake_unload_keeps = fake[i].id;
	ATF_REQUIRE(fake_unload_keeps != 0);
	ATF_CHECK_EQ(SYSEXT_DECISION_FAILED, sysext_root_unload("rlbase",
	    &error, detail, sizeof(detail)));
	ATF_CHECK_EQ(EBUSY, error);
	ATF_CHECK(strstr(detail, "still referenced") != NULL);
	ATF_CHECK(fake_loaded("rlbase.ko"));
	fake_unload_keeps = 0;
	ATF_CHECK_EQ(SYSEXT_DECISION_UNLOADED, sysext_root_unload("rltest_n",
	    &error, detail, sizeof(detail)));
	ATF_CHECK_EQ(SYSEXT_DECISION_UNLOADED, sysext_root_unload("rlbase",
	    &error, detail, sizeof(detail)));
	ATF_CHECK(!fake_loaded("rlbase.ko"));
}


/* ------------------------------------------------- hardware-driver class */

/* The name the worker's Ensure asked the (fake) kernel for, in the child. */
static int
record_ensure(const char *name, int *fileid)
{

	*fileid = 99;
	return (strcmp(name, "if_rltest") == 0 ? 0 : ENOENT);
}

/* kldxref(8) linker.hints: if_rltest.ko with a PNP table when pnp. */
static void
write_hints(const char *path, bool pnp)
{
	unsigned char buf[256];
	size_t len = 0, rec;
	int v, fd;

#define	PUT_INT(x) do {							\
	len = roundup2(len, sizeof(int));				\
	v = (x);							\
	memcpy(buf + len, &v, sizeof(int));				\
	len += sizeof(int);						\
} while (0)
#define	PUT_STR(s) do {							\
	buf[len++] = (unsigned char)strlen(s);				\
	memcpy(buf + len, s, strlen(s));				\
	len += strlen(s);						\
} while (0)
#define	END_REC() do {							\
	v = (int)(len - rec - sizeof(int));				\
	memcpy(buf + rec, &v, sizeof(int));				\
} while (0)
	PUT_INT(LINKER_HINTS_VERSION);
	rec = len = roundup2(len, sizeof(int));
	PUT_INT(0);
	PUT_INT(MDT_MODULE);
	PUT_STR("if_rltest");
	PUT_STR("if_rltest.ko");
	END_REC();
	if (pnp) {
		rec = len = roundup2(len, sizeof(int));
		PUT_INT(0);
		PUT_INT(MDT_PNP_INFO);
		PUT_STR("uhub");
		PUT_STR("U16:vendor;");
		PUT_INT(1);
		PUT_INT(0x46f4);
		END_REC();
	}
#undef PUT_INT
#undef PUT_STR
#undef END_REC
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, buf, len));
	close(fd);
}

/*
 * One devd session through the real worker (sysext_handle), then the status
 * view: what the hardware-driver class decided for each Ensure.
 */
static void
driver_round(const char *const *names, size_t n, const int *expect,
    bool stale)
{
	struct service_extension_decision d;
	struct extensioncmp_session *s;
	struct sysext_config cfg;
	int clients[2], providers[2], st;
	uint64_t after = 0;
	pid_t child;

	test_base_policy(&cfg);
	cfg.device_drivers = true;
	strlcpy(cfg.driver_clients[0], "devd", sizeof(cfg.driver_clients[0]));
	cfg.ndriver_clients = 1;
	for (int i = 0; i < 2; i++)
		channel_pair(&clients[i], &providers[i]);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		int r;

		close(clients[0]);
		close(clients[1]);
		fake_reset("/boot/kernel/kernel");
		sysext_test_kld_load = record_ensure;
		sysext_root_dirfd = open("..", O_DIRECTORY | O_RDONLY);
		sysext_boot_dirfd = open(".", O_DIRECTORY | O_RDONLY);
		if (sysext_kernel_dir_open() != 0)
			_exit(2);
		/* The directory now holds another kernel than the running one. */
		if (stale)
			sysext_test_build_id =
			    "0000000000000000000000000000000000000004";
		r = sysext_test_serve(providers[0], "devd", &cfg);
		r |= sysext_test_serve_status(providers[1], "devd", &cfg);
		_exit(r);
	}
	close(providers[0]);
	close(providers[1]);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create(clients[0], &s));
	for (size_t i = 0; i < n; i++)
		(void)extensioncmp_load(s, names[i]);
	extensioncmp_session_close(s);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_status(clients[1], &s));
	for (size_t i = 0; i < n; i++) {
		ATF_REQUIRE_EQ(0, extensioncmp_decision(s, after, &d));
		after = d.sequence;
		ATF_CHECK_STREQ(names[i], d.name);
		ATF_CHECK_EQ_MSG(expect[i], (int)d.result, "%s: %u", names[i],
		    d.result);
	}
	extensioncmp_session_close(s);
	ATF_REQUIRE_EQ(child, waitpid(child, &st, 0));
	ATF_CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/*
 * The hardware-driver class end to end: an Ensure from devd reaches the
 * kernel only for a module the running kernel's linker.hints records with a
 * PNP table; the cached hints follow a rewrite; a kernel directory that no
 * longer holds the running kernel grants nothing.
 */
ATF_TC(driver_class_ensure);
ATF_TC_HEAD(driver_class_ensure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "devd's Ensure loads a PNP driver of the running kernel only");
}
ATF_TC_BODY(driver_class_ensure, tc)
{
	static const char *const names[] = { "if_rltest", "rltest_a" };
	static const int loaded[] = { SYSEXT_DECISION_LOADED,
	    SYSEXT_DECISION_DRIVERS_ONLY };
	static const int refused[] = { SYSEXT_DECISION_DRIVERS_ONLY,
	    SYSEXT_DECISION_DRIVERS_ONLY };

	fixture_files(tc);
	write_hints("kernel/linker.hints", true);
	driver_round(names, nitems(names), loaded, false);
	/* Rewritten without the PNP table (same size class, new times). */
	usleep(20000);
	write_hints("kernel/linker.hints", false);
	driver_round(names, nitems(names), refused, false);
	/* Another kernel installed in place: nothing is a driver of it. */
	write_hints("kernel/linker.hints", true);
	driver_round(names, 1, refused, true);
}


/* ------------------------------------------------------------- endpoint */

/*
 * Serve RootLoad sessions in a child (the fake kernel lives there), then a
 * status session in the same process, so the decision ring is shared as in
 * the broker.
 */
struct endpoint {
	pid_t child;
	int clients[3];
};

static void
endpoint_start(const atf_tc_t *tc, struct endpoint *e, const char *repository,
    const char *deny, int nload)
{
	struct sysext_config cfg;
	int providers[3];

	fixture_files(tc);
	policy(&cfg, repository);
	for (int i = 0; i < nload + 1; i++)
		channel_pair(&e->clients[i], &providers[i]);
	e->child = fork();
	ATF_REQUIRE(e->child >= 0);
	if (e->child == 0) {
		int rdir, bdir, pdir, r = 0;

		for (int i = 0; i < nload + 1; i++)
			close(e->clients[i]);
		rdir = open("..", O_DIRECTORY | O_RDONLY);
		if (rdir == -1 || sysext_root_dir_limit(rdir) != 0)
			_exit(2);
		bdir = open(".", O_DIRECTORY | O_RDONLY);
		pdir = open("pkg", O_DIRECTORY | O_RDONLY);
		fake_reset("/boot/kernel/kernel");
		for (int i = 0; i < nload; i++)
			r |= sysext_test_serve_rootload(providers[i],
			    "org.5bsd.user-session", &cfg, rdir, bdir, pdir,
			    deny);
		r |= sysext_test_serve_status(providers[nload],
		    "org.5bsd.user-session", &cfg);
		_exit(r);
	}
	for (int i = 0; i < nload + 1; i++)
		close(providers[i]);
}

static void
endpoint_finish(struct endpoint *e)
{
	int st;

	ATF_REQUIRE_EQ(e->child, waitpid(e->child, &st, 0));
	ATF_CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/*
 * A root session loads a package module, its refusals carry the reason, and
 * the status view reports every decision with the root client.
 */
ATF_TC(endpoint_load_and_status);
ATF_TC_HEAD(endpoint_load_and_status, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "RootLoad loads a base package module; status shows the decisions");
}
ATF_TC_BODY(endpoint_load_and_status, tc)
{
	struct service_extension_root_outcome o;
	struct service_extension_decision d;
	struct extensioncmp_session *root, *status;
	struct endpoint e;
	static const struct { const char *name; int result; } expect[] = {
		{ "rltest_a", SYSEXT_DECISION_LOADED },
		{ "rltest_b", SYSEXT_DECISION_NOT_PACKAGED },
		{ "rltest_t", SYSEXT_DECISION_CHECKSUM },
		{ "rltest_m", SYSEXT_DECISION_NOT_KERNEL_DIR },
		{ "kernel", SYSEXT_DECISION_PRESENT },
	};
	uint64_t after = 0;

	endpoint_start(tc, &e, "5BSD-base", NULL, 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	for (size_t i = 0; i < nitems(expect); i++) {
		ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, expect[i].name,
		    &o));
		ATF_CHECK_EQ_MSG(expect[i].result, o.result, "%s: %d",
		    expect[i].name, o.result);
	}
	ATF_REQUIRE_EQ(0, extensioncmp_root_unload(root, "rltest_a", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_UNLOADED, o.result);
	ATF_REQUIRE_EQ(0, extensioncmp_root_unload(root, "rltest_b", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_NOT_ROOT_LOADED, o.result);
	/* A path is not a module name: refused before anything is sent. */
	ATF_CHECK_ERRNO(EINVAL, extensioncmp_root_load(root,
	    "../modules/rltest_m", &o) == -1);
	ATF_CHECK_ERRNO(EINVAL, extensioncmp_root_load(root,
	    "/boot/modules/rltest_m.ko", &o) == -1);
	extensioncmp_session_close(root);

	ATF_REQUIRE_EQ(0, extensioncmp_session_create_status(e.clients[1],
	    &status));
	for (size_t i = 0; i < nitems(expect) + 2; i++) {
		ATF_REQUIRE_EQ(0, extensioncmp_decision(status, after, &d));
		after = d.sequence;
		ATF_CHECK_STREQ("root (uid 0)", d.client);
		if (i < nitems(expect)) {
			ATF_CHECK_STREQ(expect[i].name, d.name);
			ATF_CHECK_EQ(SYSEXT_OP_ROOT_LOAD, d.operation);
			ATF_CHECK_EQ(expect[i].result, d.result);
		} else
			ATF_CHECK_EQ(SYSEXT_OP_ROOT_UNLOAD, d.operation);
	}
	ATF_CHECK_ERRNO(ENOENT, extensioncmp_decision(status, after, &d) == -1);
	extensioncmp_session_close(status);
	endpoint_finish(&e);
}

/*
 * Administrator denies win, for dependencies too; without
 * root_load_repository nothing loads.
 */
ATF_TC(endpoint_policy_refusals);
ATF_TC_HEAD(endpoint_policy_refusals, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A denied module and an unconfigured policy are refused");
}
ATF_TC_BODY(endpoint_policy_refusals, tc)
{
	struct service_extension_root_outcome o;
	struct extensioncmp_session *root;
	struct endpoint e;

	endpoint_start(tc, &e, "5BSD-base", "rltest_a", 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, "rltest_a", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_OVERRIDE, o.result);
	ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, "rltest_n", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, o.result);
	extensioncmp_session_close(root);
	close(e.clients[1]);
	endpoint_finish(&e);
	fixture_remove();

	/* S1: a denied dependency refuses the module that needs it. */
	endpoint_start(tc, &e, "5BSD-base", "rlbase", 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, "rltest_n", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_OVERRIDE, o.result);
	ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, "rltest_a", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_LOADED, o.result);
	extensioncmp_session_close(root);
	close(e.clients[1]);
	endpoint_finish(&e);
	fixture_remove();

	endpoint_start(tc, &e, NULL, NULL, 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	ATF_REQUIRE_EQ(0, extensioncmp_root_load(root, "rltest_a", &o));
	ATF_CHECK_EQ(SYSEXT_DECISION_DISABLED, o.result);
	extensioncmp_session_close(root);
	close(e.clients[1]);
	endpoint_finish(&e);
}

/* FIDL v2 transactional message header and a Module body. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
struct module_frame {
	uint64_t size;
	uint64_t presence;
	char name[64];
};

#define	ORD_ROOTLOAD_PROTOCOL	UINT64_C(0x3e653a95966a0d64)
#define	ORD_ROOTLOAD_LOAD	UINT64_C(0x628311e2c07df9de)
#define	ORD_ENSURE	UINT64_C(0x20729fc6bf255a8d)
#define	ORD_STAT	UINT64_C(0x318126ca32fd13e1)
#define	ORD_LIST	UINT64_C(0x27d9ac31c7bce8c3)
#define	ORD_RELOAD	UINT64_C(0x42969f6472d4b6ef)
#define	ORD_ALLOW	UINT64_C(0x3d329bc1c82f3571)
#define	ORD_RESTORE	UINT64_C(0x055ac9d5d610de33)
#define	ORD_STATUS_PROTOCOL	UINT64_C(0x29dc67c4cb8fb696)

/* -1 when the provider closed the session, else the reply's error (0 ok). */
static int
send_frame(struct service_session *session, uint64_t ordinal,
    const void *body, size_t body_length)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct wire_header header = { 3, { 2, 0, 0 }, 1, ordinal };
	uint8_t frame[256], reply[4096];
	uint64_t tag;
	uint32_t value;

	memcpy(frame, &header, sizeof(header));
	if (body_length != 0)
		memcpy(frame + sizeof(header), body, body_length);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = frame;
	outgoing.length = sizeof(header) + body_length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 5000;
	if (service_session_call(session, &outgoing, &incoming, &options) == -1)
		return (-1);
	if (incoming.length < sizeof(struct wire_header) + 16)
		return (0);
	memcpy(&tag, reply + sizeof(struct wire_header), sizeof(tag));
	memcpy(&value, reply + sizeof(struct wire_header) + 8, sizeof(value));
	return (tag == 2 ? (int)value : 0);
}

static size_t
module_frame(struct module_frame *f, const char *name)
{
	size_t length = strlen(name);

	memset(f, 0, sizeof(*f));
	f->size = length;
	f->presence = UINT64_MAX;
	memcpy(f->name, name, length);
	return (16 + ((length + 7) & ~(size_t)7));
}

/*
 * The RootLoad protocol has Load and Unload only: an Ensure, Stat, List,
 * Reload, Allow or Restore frame is an unknown ordinal and closes the session
 * unanswered, even with every right on it.  The library refuses the same
 * operations without sending anything.
 */
ATF_TC(endpoint_has_no_policy_methods);
ATF_TC_HEAD(endpoint_has_no_policy_methods, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The root-load endpoint answers no policy, list or status method");
}
ATF_TC_BODY(endpoint_has_no_policy_methods, tc)
{
	static const struct { uint64_t ordinal; bool named; } methods[] = {
		{ ORD_ENSURE, true }, { ORD_STAT, true }, { ORD_LIST, false },
		{ ORD_RELOAD, false }, { ORD_ALLOW, true },
		{ ORD_RESTORE, false }, { ORD_STATUS_PROTOCOL, false },
	};
	struct service_extension_info info;
	struct service_extension_decision d;
	struct service_session *raw;
	struct extensioncmp_session *root;
	struct module_frame body;
	struct endpoint e;
	size_t length;
	int loaded;

	for (size_t i = 0; i < nitems(methods); i++) {
		endpoint_start(tc, &e, "5BSD-base", NULL, 1);
		ATF_REQUIRE_EQ(0, service_session_create(e.clients[0], &raw));
		ATF_REQUIRE_EQ(0, send_frame(raw, ORD_ROOTLOAD_PROTOCOL, NULL,
		    0));
		length = methods[i].named ? module_frame(&body, "rltest_a") : 0;
		ATF_CHECK_EQ_MSG(-1, send_frame(raw, methods[i].ordinal, &body,
		    length), "ordinal %#jx answered on the root-load endpoint",
		    (uintmax_t)methods[i].ordinal);
		ATF_CHECK_EQ(-1, send_frame(raw, ORD_ROOTLOAD_PROTOCOL, NULL,
		    0));
		service_session_close(raw);
		close(e.clients[1]);
		endpoint_finish(&e);
		fixture_remove();
	}

	/* A malformed name is an error reply, not a decision. */
	endpoint_start(tc, &e, "5BSD-base", NULL, 1);
	ATF_REQUIRE_EQ(0, service_session_create(e.clients[0], &raw));
	ATF_REQUIRE_EQ(0, send_frame(raw, ORD_ROOTLOAD_PROTOCOL, NULL, 0));
	ATF_CHECK_EQ(EINVAL, send_frame(raw, ORD_ROOTLOAD_LOAD, &body,
	    module_frame(&body, "../modules/rltest_m")));
	ATF_CHECK_EQ(EINVAL, send_frame(raw, ORD_ROOTLOAD_LOAD, &body,
	    module_frame(&body, "..")));
	service_session_close(raw);
	close(e.clients[1]);
	endpoint_finish(&e);
	fixture_remove();

	endpoint_start(tc, &e, "5BSD-base", NULL, 1);
	ATF_REQUIRE_EQ(0, extensioncmp_session_create_rootload(e.clients[0],
	    &root));
	ATF_CHECK_ERRNO(EPERM, extensioncmp_load(root, "rltest_a") == -1);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_stat(root, "rltest_a",
	    &loaded) == -1);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_reload(root) == -1);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_manage(root,
	    SERVICE_EXTENSION_ALLOW, "rltest_a") == -1);
	ATF_CHECK_ERRNO(EPERM, extensioncmp_info(root, "rltest_a", 0,
	    &info) == -1);
	ATF_CHECK_ERRNO(EOPNOTSUPP, extensioncmp_decision(root, 0, &d) == -1);
	extensioncmp_session_close(root);
	close(e.clients[1]);
	endpoint_finish(&e);
}

/* The policy key: a repository name, at most once, nothing else. */
ATF_TC_WITHOUT_HEAD(policy_key);
ATF_TC_BODY(policy_key, tc)
{
	struct sysext_config cfg;
	static const char *const bad[] = {
		"root_load_repository = 42; allowed_extensions = [];",
		"root_load_repository = \"a/b\"; allowed_extensions = [];",
		"root_load_repository = \"\"; allowed_extensions = [];",
		"root_load_repository = [\"5BSD-base\"]; allowed_extensions = [];",
		("root_load_repository = \"x\"; root_load_repository = \"y\"; "
		    "allowed_extensions = [];"),
	};

	(void)tc;
	write_file("good.ucl", "root_load_repository = \"5BSD-base\"; "
	    "device_drivers = true; driver_clients = [\"devd\"]; "
	    "allowed_extensions = [\"zfs\"];");
	ATF_REQUIRE_EQ(0, chmod("good.ucl", 0644));
	sysext_config_defaults(&cfg);
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg, "good.ucl"));
	ATF_CHECK_STREQ("5BSD-base", cfg.root_load_repository);
	write_file("none.ucl", "allowed_extensions = [];");
	ATF_REQUIRE_EQ(0, sysext_config_load(&cfg, "none.ucl"));
	ATF_CHECK_STREQ("", cfg.root_load_repository);
	for (size_t i = 0; i < nitems(bad); i++) {
		write_file("bad.ucl", bad[i]);
		ATF_CHECK_MSG(sysext_config_load(&cfg, "bad.ucl") == -1,
		    "accepted: %s", bad[i]);
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, checksum_matches_pkg);
	ATF_TP_ADD_TC(tp, pkgdb_lookup);
	ATF_TP_ADD_TC(tp, load_package_module);
	ATF_TP_ADD_TC(tp, refuse_unpackaged_file);
	ATF_TP_ADD_TC(tp, refuse_tampered_checksum);
	ATF_TP_ADD_TC(tp, refuse_outside_kernel_dir);
	ATF_TP_ADD_TC(tp, pkgdb_hostile);
	ATF_TP_ADD_TC(tp, refuse_protected);
	ATF_TP_ADD_TC(tp, dependency_outside_kernel_dir);
	ATF_TP_ADD_TC(tp, dependency_checked_before_load);
	ATF_TP_ADD_TC(tp, dependency_loaded_first);
	ATF_TP_ADD_TC(tp, dependency_version_mismatch);
	ATF_TP_ADD_TC(tp, unexpected_file_undone);
	ATF_TP_ADD_TC(tp, kldstat_failure_refused);
	ATF_TP_ADD_TC(tp, changed_with_mtime_restored);
	ATF_TP_ADD_TC(tp, kernel_dir_replaced);
	ATF_TP_ADD_TC(tp, kernel_replaced_in_place);
	ATF_TP_ADD_TC(tp, kernel_dir_from_boot_path);
	ATF_TP_ADD_TC(tp, driver_class_ensure);
	ATF_TP_ADD_TC(tp, refuse_without_database);
	ATF_TP_ADD_TC(tp, boot_replaced);
	ATF_TP_ADD_TC(tp, boot_replaced_during_load);
	ATF_TP_ADD_TC(tp, dependency_loaded_out_of_range);
	ATF_TP_ADD_TC(tp, foreign_load_left_loaded);
	ATF_TP_ADD_TC(tp, checks_outside_load_lock);
	ATF_TP_ADD_TC(tp, unload_still_referenced);
	ATF_TP_ADD_TC(tp, endpoint_load_and_status);
	ATF_TP_ADD_TC(tp, endpoint_policy_refusals);
	ATF_TP_ADD_TC(tp, endpoint_has_no_policy_methods);
	ATF_TP_ADD_TC(tp, policy_key);
	return (atf_no_error());
}
