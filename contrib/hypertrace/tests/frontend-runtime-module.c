/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dt_module.c over synthetic module objects (see frontend-runtime-module.py).
 * The kernel linker enumeration is replaced by frontend-runtime-shim.so so
 * that dtrace_update() sees exactly the objects listed below.  expect.txt,
 * written by the driver's own ELF reader, holds the expected module ranges
 * and symbol values; types are checked against the declarations compiled
 * into the objects (struct foo { int a; long b; } is 16 bytes in LP64 and
 * 8 in ILP32, struct fwd is completed only in fwdmod, and childmod's CTF
 * names parentmod as its parent).
 */
#include <sys/types.h>
#include <sys/wait.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <dt_impl.h>
#include <dt_module.h>
#include <libctf.h>

#include "frontend-faults.h"
#include "frontend-runtime-shim.h"

static void (*shim_klds)(const struct frontend_shim_kld *, int);
static const char *moddir;
static char paths[32][PATH_MAX];

#define	ADDR64	0xffffffff82000000UL
#define	ADDR32	0xc1000000UL

/* Must match the driver's module list (fileid = index + 1). */
static struct frontend_shim_kld klds[] = {
	{ 1, "m64rel", "m64rel.ko", ADDR64, 0, { "m64rel_mod", "shared_mod" } },
	{ 2, "fwdmod", "fwdmod.ko", ADDR64 + 0x100000, 0,
	    { "fwd_mod", "shared_mod", "!fail" } },
	{ 3, "m64dyn", "m64dyn.ko", ADDR64 + 0x200000, 0, { NULL } },
	{ 4, "m32rel", "m32rel.ko", ADDR32, 0, { "m32_mod" } },
	{ 5, "noctf", "noctf.ko", ADDR64 + 0x400000, 0, { NULL } },
	{ 6, "badctf", "badctf.ko", ADDR64 + 0x500000, 0, { NULL } },
	{ 7, "PARENT", "parentmod.ko", ADDR64 + 0x600000, 0, { NULL } },
	{ 8, "childmod", "childmod.ko", ADDR64 + 0x700000, 0, { NULL } },
	{ 9, "align0", "align0.ko", ADDR64 + 0x800000, 0, { NULL } },
	/* Failures: kldstat error, missing file, not ELF, unknown class. */
	{ 10, "statfail", "m64rel.ko", ADDR64, 1, { NULL } },
	{ 11, "missing", "no-such-file.ko", ADDR64, 0, { NULL } },
	{ 12, "notelf", "notelf.ko", ADDR64, 0, { NULL } },
	{ 13, "classnone", "classnone.ko", ADDR64, 0, { NULL } },
	{ 14, "orphan", "orphan.ko", ADDR64 + 0x900000, 0, { NULL } },
	{ 15, "SELFPA", "selfpa.ko", ADDR64 + 0xa00000, 0, { NULL } },
	{ 16, "m32dyn", "m32dyn.ko", ADDR32 + 0x100000, 0, { NULL } },
	{ 17, "stripped", "stripped.ko", ADDR64 + 0xb00000, 0, { NULL } },
	{ 18, "malformed", "malformed.ko", ADDR64 + 0xc00000, 0, { NULL } },
	{ 19, "genunix", "genunix.ko", ADDR64 + 0x10000000, 0, { NULL } },
	{ 20, "krtld", "krtld.ko", ADDR64 + 0x20000000, 0, { NULL } },
	{ 21, "m32tie", "m32tie.ko", ADDR32 + 0x200000, 0, { NULL } },
	{ 22, "m32nosym", "m32nosym.ko", ADDR32 + 0x300000, 0, { NULL } },
	{ 23, "m32tierev", "m32tierev.ko", ADDR32 + 0x400000, 0, { NULL } },
	{ 24, "m64tie", "m64tie.ko", ADDR64 + 0xd00000, 0, { NULL } },
	{ 25, "m64tierev", "m64tierev.ko", ADDR64 + 0xe00000, 0, { NULL } },
	{ 26, "nosect", "nosect.ko", ADDR64 + 0xf00000, 0, { NULL } },
	{ 27, "m32noabs", "m32noabs.ko", ADDR32 + 0x500000, 0, { NULL } },
	{ 28, "m64small", "m64small.ko", ADDR64 + 0x1000000, 0, { NULL } },
	{ 29, "m32small", "m32small.ko", ADDR32 + 0x600000, 0, { NULL } },
};
#define	NKLDS	((int)(sizeof (klds) / sizeof (klds[0])))
static int nklds_active = NKLDS;

static void
bind_shim(void)
{
	int (*active)(void) = (int (*)(void))dlsym(RTLD_DEFAULT,
	    "frontend_shim_active");
	int i;

	if (active == NULL || active() != 1) {
		printf("FAIL frontend-runtime-shim.so is not preloaded\n");
		exit(2);
	}
	shim_klds = dlsym(RTLD_DEFAULT, "frontend_shim_klds");
	for (i = 0; i < NKLDS; i++) {
		(void) snprintf(paths[i], sizeof (paths[i]), "%s/%s", moddir,
		    klds[i].path);
		klds[i].path = paths[i];
	}
}

static dtrace_hdl_t *
mopen(int flags)
{
	int err;
	dtrace_hdl_t *dtp;

	shim_klds(klds, nklds_active);
	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV | DTRACE_O_NOSYS |
	    flags, &err);
	if (dtp == NULL) {
		printf("FAIL dtrace_open: %s\n", dtrace_errmsg(NULL, err));
		exit(2);
	}
	(void) dtrace_setopt(dtp, "nolibs", NULL);
	return (dtp);
}

/* ---- expectations ---------------------------------------------------- */

struct eobj {
	char name[32];
	uint64_t text_va, text_size, data_va, data_size, bss_va, bss_size;
	int primary;
	int seen;
};
struct esym {
	char obj[32], name[64];
	uint64_t value, size;
	int type, bind;
};
static struct eobj eobjs[32];
static struct esym esyms[1024];
static int neobjs, nesyms, ngaps, nedges;
static struct { char obj[32]; uint64_t lo, hi; } edges[32];
static struct { char obj[32]; uint64_t addr; } gaps[32];

static void
load_expect(const char *path)
{
	FILE *fp = fopen(path, "r");
	char kind[8];

	if (fp == NULL) {
		printf("FAIL cannot read %s\n", path);
		exit(2);
	}
	while (fscanf(fp, "%7s", kind) == 1) {
		if (strcmp(kind, "obj") == 0 && neobjs < 32) {
			struct eobj *o = &eobjs[neobjs++];

			(void) fscanf(fp, "%31s %jx %jx %jx %jx %jx %jx %d", o->name,
			    (uintmax_t *)&o->text_va, (uintmax_t *)&o->text_size,
			    (uintmax_t *)&o->data_va, (uintmax_t *)&o->data_size,
			    (uintmax_t *)&o->bss_va, (uintmax_t *)&o->bss_size,
			    &o->primary);
		} else if (strcmp(kind, "edge") == 0 && nedges < 32) {
			(void) fscanf(fp, "%31s %jx %jx", edges[nedges].obj,
			    (uintmax_t *)&edges[nedges].lo,
			    (uintmax_t *)&edges[nedges].hi);
			nedges++;
		} else if (strcmp(kind, "gap") == 0 && ngaps < 32) {
			(void) fscanf(fp, "%31s %jx", gaps[ngaps].obj,
			    (uintmax_t *)&gaps[ngaps].addr);
			ngaps++;
		} else if (strcmp(kind, "sym") == 0 && nesyms < 1024) {
			struct esym *s = &esyms[nesyms++];

			(void) fscanf(fp, "%31s %63s %jx %jx %d %d", s->obj, s->name,
			    (uintmax_t *)&s->value, (uintmax_t *)&s->size, &s->type,
			    &s->bind);
		}
	}
	fclose(fp);
}

static int
obj_cb(dtrace_hdl_t *dtp, const dtrace_objinfo_t *dto, void *arg)
{
	int i;

	(void) dtp; (void) arg;
	for (i = 0; i < neobjs; i++) {
		struct eobj *o = &eobjs[i];

		if (strcmp(o->name, dto->dto_name) != 0)
			continue;
		o->seen++;
		check(dto->dto_text_va == o->text_va &&
		    dto->dto_text_size == o->text_size &&
		    dto->dto_data_va == o->data_va &&
		    dto->dto_data_size == o->data_size &&
		    dto->dto_bss_va == o->bss_va &&
		    dto->dto_bss_size == o->bss_size,
		    "%s ranges: text %#jx+%#jx data %#jx+%#jx bss %#jx+%#jx "
		    "(want text %#jx+%#jx data %#jx+%#jx bss %#jx+%#jx)",
		    o->name, (uintmax_t)dto->dto_text_va,
		    (uintmax_t)dto->dto_text_size, (uintmax_t)dto->dto_data_va,
		    (uintmax_t)dto->dto_data_size, (uintmax_t)dto->dto_bss_va,
		    (uintmax_t)dto->dto_bss_size, (uintmax_t)o->text_va,
		    (uintmax_t)o->text_size, (uintmax_t)o->data_va,
		    (uintmax_t)o->data_size, (uintmax_t)o->bss_va,
		    (uintmax_t)o->bss_size);
		check((dto->dto_flags & DTRACE_OBJ_F_KERNEL) &&
		    !!(dto->dto_flags & DTRACE_OBJ_F_PRIMARY) == o->primary,
		    "%s flags %#x", o->name, dto->dto_flags);
	}
	return (0);
}

static int
stop_cb(dtrace_hdl_t *dtp, const dtrace_objinfo_t *dto, void *arg)
{
	(void) dtp; (void) dto;
	return (++*(int *)arg == 3 ? 9 : 0);
}

static void
test_objects(void)
{
	dtrace_hdl_t *dtp = mopen(0);
	dtrace_objinfo_t dto;
	int i, n = 0;

	check(dtrace_object_iter(dtp, obj_cb, NULL) == 0, "object iteration");
	for (i = 0; i < neobjs; i++)
		check(eobjs[i].seen == 1, "module %s listed once (%d)",
		    eobjs[i].name, eobjs[i].seen);
	check(dtrace_object_iter(dtp, stop_cb, &n) == 9 && n == 3,
	    "object iteration stops on a callback value");
	/* Modules whose files could not be used are not listed. */
	for (i = 9; i < 13; i++)
		check(dt_module_lookup_by_name(dtp, klds[i].name) == NULL,
		    "%s not loaded", klds[i].name);
	check(dtrace_object_info(dtp, "m64rel", &dto) == 0 &&
	    strcmp(dto.dto_file, klds[0].path) == 0 && dto.dto_id == 1,
	    "object info names the file and id");
	check(dtrace_object_info(dtp, DTRACE_OBJ_EVERY, &dto) == -1 &&
	    dtrace_errno(dtp) == EINVAL, "object info rejects EVERY");
	check(dtrace_object_info(dtp, "m64rel", NULL) == -1 &&
	    dtrace_errno(dtp) == EINVAL, "object info needs a buffer");
	check(dtrace_object_info(dtp, "nosuchmod", &dto) == -1 &&
	    dtrace_errno(dtp) == EDT_NOTLOADED,
	    "unknown object cannot be loaded (%d)", dtrace_errno(dtp));
	check(dtrace_object_info(dtp, DTRACE_OBJ_CDEFS, &dto) == 0 &&
	    strcmp(dto.dto_name, "C") == 0, "C object");
	/* genunix is the executable module (moved to the front of the
	 * module list on first update) and krtld the runtime linker. */
	check(dtrace_object_info(dtp, DTRACE_OBJ_EXEC, &dto) == 0 &&
	    strcmp(dto.dto_name, "genunix") == 0, "genunix executable module");
	check(dtrace_object_info(dtp, DTRACE_OBJ_RTLD, &dto) == 0 &&
	    strcmp(dto.dto_name, "krtld") == 0, "krtld runtime linker module");
	{
		/* dt_vopen() then puts the C and D containers before it. */
		dt_module_t *m1 = dt_list_next(&dtp->dt_modlist);
		dt_module_t *m3 = dt_list_next(dt_list_next(m1));

		check(strcmp(m1->dm_name, "C") == 0 &&
		    strcmp(m3->dm_name, "genunix") == 0,
		    "module list starts C, D, genunix (%s ... %s)",
		    m1->dm_name, m3->dm_name);
	}
	check(dtrace_object_info(dtp, DTRACE_OBJ_KMODS, &dto) == -1 &&
	    dtrace_errno(dtp) == EINVAL &&
	    dtrace_object_info(dtp, DTRACE_OBJ_UMODS, &dto) == -1 &&
	    dtrace_errno(dtp) == EINVAL, "object info rejects KMODS/UMODS");
	/* Kernel module aliases from modstat(). */
	check(dt_kmodule_lookup(dtp, "m64rel_mod") != NULL &&
	    dt_kmodule_lookup(dtp, "m64rel_mod")->dkm_module ==
	    dt_module_lookup_by_name(dtp, "m64rel") &&
	    dt_kmodule_lookup(dtp, "shared_mod")->dkm_module ==
	    dt_module_lookup_by_name(dtp, "m64rel") &&
	    dt_kmodule_lookup(dtp, "fwd_mod") != NULL &&
	    dt_kmodule_lookup(dtp, "nosuch_mod") == NULL,
	    "kernel module aliases (first file keeps a shared name)");
	/* dtrace_update() reloads from scratch and finds the same modules. */
	dtrace_update(dtp);
	for (i = 0; i < neobjs; i++)
		eobjs[i].seen = 0;
	check(dtrace_object_iter(dtp, obj_cb, NULL) == 0, "after update");
	dtrace_close(dtp);
}

static void
test_symbols(int flags)
{
	dtrace_hdl_t *dtp = mopen(flags);
	dtrace_syminfo_t si;
	GElf_Sym sym;
	int i, rc;

	for (i = 0; i < nesyms; i++) {
		struct esym *s = &esyms[i];

		memset(&sym, 0, sizeof (sym));
		rc = dtrace_lookup_by_name(dtp, s->obj, s->name, &sym, &si);
		check(rc == 0 && sym.st_value == s->value &&
		    sym.st_size == s->size && strcmp(si.dts_name, s->name) == 0 &&
		    strcmp(si.dts_object, s->obj) == 0,
		    "%s`%s value %#jx (want %#jx) rc %d", s->obj, s->name,
		    (uintmax_t)sym.st_value, (uintmax_t)s->value, rc);
	}
	/* Address lookups pick the preferred symbol at an address: sized,
	 * typed, not weak, then lexically first (alias_f before f). */
	for (i = 0; i < nesyms; i++) {
		struct esym *s = &esyms[i];

		if (strcmp(s->name, "f") != 0 || strcmp(s->obj, "m64rel") != 0)
			continue;
		rc = dtrace_lookup_by_addr(dtp, s->value + 1, &sym, &si);
		check(rc == 0 && strcmp(si.dts_name, "alias_f") == 0 &&
		    strcmp(si.dts_object, "m64rel") == 0,
		    "address inside f resolves to alias_f (%s)",
		    rc == 0 ? si.dts_name : "none");
		rc = dtrace_lookup_by_addr(dtp, s->value, NULL, &si);
		check(rc == 0 && si.dts_name == NULL &&
		    strcmp(si.dts_object, "m64rel") == 0,
		    "address lookup without a symbol buffer names the module");
	}
	/* 32-bit preference order at f's address: sized, typed, not weak,
	 * then lexically first; alias_f and f tie, alias_f sorts first. */
	for (i = 0; i < nesyms; i++) {
		struct esym *s = &esyms[i];

		if (strstr(s->obj, "tie") == NULL || strcmp(s->name, "f") != 0)
			continue;
		rc = dtrace_lookup_by_addr(dtp, s->value + 1, &sym, &si);
		check(rc == 0 && strcmp(si.dts_name, "alias_f") == 0,
		    "%s tie-break picks alias_f (%s)", s->obj,
		    rc == 0 ? si.dts_name : "none");
	}
	/* The lowest and highest address-mapped symbols of each module. */
	for (i = 0; i < nedges; i++) {
		rc = dtrace_lookup_by_addr(dtp, edges[i].lo, &sym, &si);
		check(rc == 0 && sym.st_value == edges[i].lo &&
		    strcmp(si.dts_object, edges[i].obj) == 0,
		    "%s lowest symbol at %#jx", edges[i].obj,
		    (uintmax_t)edges[i].lo);
		check(dtrace_lookup_by_addr(dtp, edges[i].lo, &sym, NULL) == 0 &&
		    sym.st_value == edges[i].lo,
		    "%s address lookup without symbol information",
		    edges[i].obj);
		rc = dtrace_lookup_by_addr(dtp, edges[i].hi, &sym, &si);
		check(rc == 0 && sym.st_value == edges[i].hi &&
		    strcmp(si.dts_object, edges[i].obj) == 0,
		    "%s highest symbol at %#jx", edges[i].obj,
		    (uintmax_t)edges[i].hi);
	}
	for (i = 0; i < neobjs; i++)
		if (strcmp(eobjs[i].name, "m32nosym") == 0)
			check(dtrace_lookup_by_addr(dtp, eobjs[i].text_va + 1,
			    &sym, &si) == -1 && dtrace_errno(dtp) ==
			    EDT_NOSYMADDR, "32-bit module without symbols");
	for (i = 0; i < nesyms; i++) {
		struct esym *s = &esyms[i];

		if (strcmp(s->obj, "m32rel") != 0 || strcmp(s->name, "gdata"))
			continue;
		rc = dtrace_lookup_by_addr(dtp, s->value, &sym, &si);
		check(rc == 0 && strcmp(si.dts_name, "gdata") == 0,
		    "32-bit module address lookup");
	}
	check(dtrace_lookup_by_addr(dtp, 0x1000, &sym, &si) == -1 &&
	    dtrace_errno(dtp) == EDT_NOSYMADDR, "address outside modules");
	check(dtrace_lookup_by_name(dtp, DTRACE_OBJ_KMODS, "bfunc", &sym,
	    &si) == 0 && strcmp(si.dts_object, "fwdmod") == 0,
	    "kernel-module search");
	check(dtrace_lookup_by_name(dtp, DTRACE_OBJ_UMODS, "bfunc", &sym,
	    &si) == -1 && dtrace_errno(dtp) == EDT_NOSYM,
	    "user-module search skips kernel modules");
	check(dtrace_lookup_by_name(dtp, DTRACE_OBJ_EVERY, "bfunc", NULL,
	    NULL) == 0, "lookup without result buffers");
	check(dtrace_lookup_by_name(dtp, "m64rel", "nosuchsym", &sym, &si) ==
	    -1 && dtrace_errno(dtp) == EDT_NOSYM, "missing symbol");
	check(dtrace_lookup_by_name(dtp, "nosuchmod", "f", &sym, &si) == -1,
	    "symbol in unknown module");
	check(dtrace_lookup_by_name(dtp, DTRACE_OBJ_RTLD, "f", &sym, &si) ==
	    0 && strcmp(si.dts_object, "krtld") == 0, "runtime linker module");
	/* Addresses: in BSS, in a gap after the last text symbol, in a
	 * module without symbols. */
	for (i = 0; i < nesyms; i++) {
		struct esym *s = &esyms[i];

		/*
		 * Only relocatable modules: for other objects dt_module_update
		 * packs the section ranges from the load address while symbols
		 * are relocated by the first PT_LOAD, so the two agree only
		 * when the sections are packed in the file (as in the kernel).
		 */
		if (strcmp(s->name, "gfoo") != 0 ||
		    strstr(s->obj, "dyn") != NULL)
			continue;
		rc = dtrace_lookup_by_addr(dtp, s->value + 2, &sym, &si);
		check(rc == 0 && strcmp(si.dts_name, "gfoo") == 0 &&
		    strcmp(si.dts_object, s->obj) == 0,
		    "%s: BSS address resolves to gfoo", s->obj);
	}
	for (i = 0; i < ngaps; i++) {
		rc = dtrace_lookup_by_addr(dtp, gaps[i].addr, &sym, &si);
		check(rc == -1 && dtrace_errno(dtp) == EDT_NOSYMADDR,
		    "%s: uncovered text address %#jx (%s`%s)", gaps[i].obj,
		    (uintmax_t)gaps[i].addr, rc == 0 ? si.dts_object : "",
		    rc == 0 ? si.dts_name : "");
	}
	for (i = 0; i < neobjs; i++) {
		if (strcmp(eobjs[i].name, "stripped") != 0)
			continue;
		check(dtrace_lookup_by_addr(dtp, eobjs[i].text_va + 1, &sym,
		    &si) == -1 && dtrace_errno(dtp) == EDT_NOSYMADDR,
		    "module without symbols: address");
	}
	check(dtrace_lookup_by_name(dtp, "stripped", "f", &sym, &si) == -1 &&
	    dtrace_errno(dtp) == EDT_NOSYM, "module without symbols: name");
	dtrace_close(dtp);
}

static ssize_t
tsize(dtrace_hdl_t *dtp, const char *obj, const char *name, const char **in)
{
	dtrace_typeinfo_t t;

	if (dtrace_lookup_by_type(dtp, obj, name, &t) != 0)
		return (-dtrace_errno(dtp));
	if (in != NULL)
		*in = t.dtt_object;
	return (ctf_type_size(t.dtt_ctfp, t.dtt_type));
}

static void
test_types(void)
{
	dtrace_hdl_t *dtp = mopen(0);
	dtrace_typeinfo_t t;
	const char *in = NULL;
	GElf_Sym sym;
	dtrace_syminfo_t si;
	char buf[64];

	check(tsize(dtp, "m64rel", "struct foo", NULL) == 16,
	    "m64rel struct foo is 16 bytes");
	check(tsize(dtp, DTRACE_OBJ_EVERY, "struct fwd", &in) == 8 &&
	    in != NULL && strcmp(in, "fwdmod") == 0,
	    "forward declaration resolved in a later module");
	check(dtrace_lookup_by_type(dtp, "m64rel", "struct fwd", &t) == 0 &&
	    ctf_type_kind(t.dtt_ctfp, t.dtt_type) == CTF_K_FORWARD,
	    "m64rel alone only has the forward declaration");
	check(tsize(dtp, "m32rel", "struct foo", NULL) == -EDT_DATAMODEL,
	    "32-bit CTF refused in an LP64 handle");
	check(tsize(dtp, "noctf", "int", NULL) == -EDT_NOCTF, "no CTF");
	check(tsize(dtp, "badctf", "int", NULL) == -EDT_CTF, "corrupt CTF");
	check(tsize(dtp, "childmod", "struct child_t", NULL) == 16,
	    "child CTF with parent types");
	check(tsize(dtp, "childmod", "struct shared_t", &in) == 8,
	    "parent type through the child");
	check(tsize(dtp, "orphan", "struct child_t", NULL) == -EDT_NOTLOADED,
	    "child of an absent parent (%zd)",
	    tsize(dtp, "orphan", "struct child_t", NULL));
	check(tsize(dtp, "SELFPA", "struct child_t", NULL) == -EDT_CTF,
	    "child naming itself as parent (%zd)",
	    tsize(dtp, "SELFPA", "struct child_t", NULL));
	check(tsize(dtp, DTRACE_OBJ_KMODS, "struct nosuch_t", NULL) ==
	    -EDT_NOTYPE, "missing type");
	check(tsize(dtp, DTRACE_OBJ_UMODS, "int", NULL) == 4,
	    "user search reaches the C container");
	check(dtrace_lookup_by_type(dtp, "m64rel", "struct foo", NULL) == 0,
	    "type lookup without a buffer");
	check(dt_module_hasctf(dtp, dt_module_lookup_by_name(dtp, "m64rel")),
	    "hasctf");
	check(strcmp(dt_module_modelname(dt_module_lookup_by_name(dtp,
	    "m32rel")), "32-bit") == 0 && strcmp(dt_module_modelname(
	    dt_module_lookup_by_name(dtp, "m64rel")), "64-bit") == 0,
	    "model names");
	/* Symbol types: data symbols through CTF, functions as pointers. */
	if (dtrace_lookup_by_name(dtp, "m64rel", "gfoo", &sym, &si) == 0) {
		check(dtrace_symbol_type(dtp, &sym, &si, &t) == 0 &&
		    ctf_type_name(t.dtt_ctfp, t.dtt_type, buf, sizeof (buf)) !=
		    NULL && strcmp(buf, "struct foo") == 0,
		    "type of gfoo is struct foo (%s)", buf);
	} else
		check(0, "gfoo symbol");
	if (dtrace_lookup_by_name(dtp, "m64rel", "f", &sym, &si) == 0)
		check(dtrace_symbol_type(dtp, &sym, &si, &t) == 0 &&
		    t.dtt_type == DT_FPTR_TYPE(dtp), "function symbol type");
	if (dtrace_lookup_by_name(dtp, "noctf", "gdata", &sym, &si) == 0)
		check(dtrace_symbol_type(dtp, &sym, &si, &t) == -1 &&
		    dtrace_errno(dtp) == EDT_NOCTF, "symbol type without CTF");
	/* An undefined symbol of a module without extern declarations is
	 * typed from CTF, which has no data object for it. */
	if (dtrace_lookup_by_name(dtp, "m64rel", "undefined_ext", &sym,
	    &si) == 0)
		check(sym.st_shndx == SHN_UNDEF &&
		    dtrace_symbol_type(dtp, &sym, &si, &t) == -1 &&
		    dtrace_errno(dtp) == EDT_CTF, "undefined symbol type");
	else
		check(0, "undefined_ext symbol");
	/* An untyped absolute symbol has no CTF data object entry. */
	if (dtrace_lookup_by_name(dtp, "m64rel", "abs_sym", &sym, &si) == 0)
		check(dtrace_symbol_type(dtp, &sym, &si, &t) == -1 &&
		    dtrace_errno(dtp) == EDT_CTF, "symbol without CTF type");
	else
		check(0, "abs_sym symbol");
	/* A kernel symbol referenced from D becomes an extern ident. */
	check(dtrace_program_strcompile(dtp,
	    "BEGIN { trace(m64rel`gdata); trace(m64rel`gfoo.b); }",
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL) != NULL && dtp->dt_externs != NULL,
	    "kernel symbol reference: %s", dtrace_errmsg(dtp, dtrace_errno(dtp)));
	si.dts_object = "nosuchmod";
	check(dtrace_symbol_type(dtp, &sym, &si, &t) == -1 &&
	    dtrace_errno(dtp) == EDT_NOMOD, "symbol type of unknown module");
	/* D extern declarations create undefined symbols in a module. */
	check(dtrace_program_strcompile(dtp,
	    "extern int newsym; extern long newsym2;\n"
	    "BEGIN { trace(1); }", DTRACE_PROBESPEC_NAME, 0, 0, NULL) != NULL,
	    "extern declarations: %s", dtrace_errmsg(dtp, dtrace_errno(dtp)));
	check(dtrace_lookup_by_name(dtp, DTRACE_OBJ_DDEFS, "newsym", &sym,
	    &si) == 0 && strcmp(si.dts_object, "D") == 0 && sym.st_shndx == SHN_UNDEF && sym.st_size == 4 &&
	    strcmp(si.dts_name, "newsym") == 0, "extern symbol lookup");
	check(dtrace_lookup_by_name(dtp, DTRACE_OBJ_DDEFS, "newsym", &sym,
	    NULL) == 0 && sym.st_size == 4,
	    "extern symbol lookup without symbol information");
	check(dtrace_lookup_by_name(dtp, DTRACE_OBJ_EVERY, "newsym2", NULL,
	    &si) == 0,
	    "extern symbol lookup without a symbol buffer");
	if (dtrace_lookup_by_name(dtp, DTRACE_OBJ_DDEFS, "newsym", &sym,
	    &si) == 0) {
		check(dtrace_symbol_type(dtp, &sym, &si, &t) == 0 &&
		    ctf_type_size(t.dtt_ctfp, t.dtt_type) == 4,
		    "extern symbol type");
		si.dts_name = "nosuchextern";
		check(dtrace_symbol_type(dtp, &sym, &si, &t) == -1 &&
		    dtrace_errno(dtp) == EDT_NOSYM, "unknown extern");
	}
	dtrace_close(dtp);

	/* An ILP32 handle accepts the 32-bit CTF and refuses 64-bit CTF. */
	dtp = mopen(DTRACE_O_ILP32);
	check(tsize(dtp, "m32rel", "struct foo", NULL) == 8,
	    "ILP32 struct foo is 8 bytes");
	check(tsize(dtp, "m64rel", "struct foo", NULL) == -EDT_DATAMODEL,
	    "64-bit CTF refused in an ILP32 handle");
	dtrace_close(dtp);
}

static pid_t
spawn(const char *prog)
{
	int pfd[2];
	char c, path[PATH_MAX];
	pid_t pid;

	(void) snprintf(path, sizeof (path), "%s/%s", moddir, prog);
	if (pipe(pfd) != 0)
		return (-1);
	if ((pid = fork()) == 0) {
		int null = open("/dev/null", O_RDWR);

		/* Do not hold the harness's output open if it dies. */
		(void) dup2(pfd[1], 3);
		(void) dup2(null, 1);
		(void) dup2(null, 2);
		(void) execl(path, prog, (char *)NULL);
		_exit(127);	/* exec failed: nothing to profile */
	}
	close(pfd[1]);
	if (read(pfd[0], &c, 1) != 1)
		pid = -1;
	close(pfd[0]);
	return (pid);
}

static void
reap(pid_t pid)
{
	int status;

	if (pid > 0) {
		(void) kill(pid, SIGKILL);
		(void) waitpid(pid, &status, 0);
	}
}

/* Types from a live process's CTF, loaded read-only through libproc. */
static void
test_process_ctf(void)
{
	dtrace_hdl_t *dtp = mopen(0);
	dtrace_typeinfo_t t;
	dt_module_t *dmp;
	char obj[32];
	pid_t pid = spawn("target"), npid = spawn("target_noctf");

	check(pid > 0 && npid > 0, "target processes started");
	(void) snprintf(obj, sizeof (obj), "pid%d", (int)pid);
	check(tsize(dtp, obj, "struct tfoo", NULL) == 24,
	    "struct tfoo from the process is 24 bytes");
	check(tsize(dtp, obj, "target`struct tfoo", NULL) == 24,
	    "library-qualified type");
	check(tsize(dtp, obj, "nosuchlib`int", NULL) == -EDT_NOTYPE,
	    "unknown library");
	check(tsize(dtp, obj, "target`struct nosuch", NULL) == -EDT_NOTYPE,
	    "unknown type in a known library");
	check(tsize(dtp, obj, "LM0`target`struct tfoo", NULL) == -EDT_NOTYPE,
	    "link-map qualified name for the base link map");
	check(tsize(dtp, obj, "struct nosuch", NULL) == -EDT_NOTYPE,
	    "unknown type in every library");
	dmp = dt_module_lookup_by_name(dtp, obj);
	check(dmp != NULL && dt_module_hasctf(dtp, dmp) &&
	    dmp->dm_nctflibs >= 1, "process module has CTF libraries");
	if (dmp != NULL && dmp->dm_nctflibs >= 1) {
		ctf_file_t *fp = dt_module_getctflib(dtp, dmp, "target");

		check(fp != NULL && dt_module_getlibid(dtp, dmp, fp) >= 0 &&
		    dt_module_lookup_by_ctf(dtp, fp) == dmp,
		    "library container and id");
		check(dt_module_getctflib(dtp, dmp, "nosuchlib") == NULL,
		    "unknown library container");
		check(dt_module_getlibid(dtp, dmp, NULL) == -1,
		    "container not among the process libraries");
	}
	(void) snprintf(obj, sizeof (obj), "pid%d", (int)npid);
	check(tsize(dtp, obj, "int", NULL) == -EDT_CANTLOAD,
	    "process without CTF");
	dtrace_close(dtp);
	reap(pid);
	reap(npid);
}

static void
test_pid_modules(void)
{
	dtrace_hdl_t *dtp = mopen(0);
	dt_module_t *dmp;

	dmp = dt_module_create(dtp, "pid4242");
	check(dmp != NULL && dmp->dm_pid == 4242, "pidN module");
	dmp = dt_module_create(dtp, "pidx");
	check(dmp != NULL && dmp->dm_pid == 0, "malformed pid module");
	dmp = dt_module_create(dtp, "pid12abc");
	check(dmp != NULL && dmp->dm_pid == 0, "pid module with trailing text");
	dmp = dt_module_create(dtp, "pid");
	check(dmp != NULL && dmp->dm_pid == 0, "pid module without target");
	dt_module_destroy(dtp, dmp);
	dt_idhash_lookup(dtp->dt_macros, "target")->di_id = 31337;
	dmp = dt_module_create(dtp, "pid");
	check(dmp != NULL && dmp->dm_pid == 31337, "pid module is pid$target");
	dt_idhash_lookup(dtp->dt_macros, "target")->di_id = 0;
	check(dt_module_create(dtp, "pid4242") ==
	    dt_module_lookup_by_name(dtp, "pid4242"), "create finds existing");
	/* Process 999999 does not exist: CTF cannot be loaded. */
	dmp = dt_module_create(dtp, "pid999999");
	check(dmp != NULL && dt_module_load(dtp, dmp) == -1 &&
	    dtrace_errno(dtp) == EDT_CANTLOAD, "absent process");
	check(dt_module_getlibid(dtp, dmp, NULL) == -1 &&
	    dt_module_getctflib(dtp, dmp, "libc.so.7") == NULL,
	    "no process libraries");
	dtrace_close(dtp);
}

#ifdef WITH_FAULTS
static void
fault_sweep(void)
{
	long n;
	int done;

	/* Module discovery and symbol/CTF loading under allocation failure;
	 * every outcome must leave a usable handle or a clean error. */
	for (n = 1, done = 0; !done && n < 20000; n++) {
		dtrace_hdl_t *dtp;
		int err, rc = 0;
		GElf_Sym sym;
		dtrace_typeinfo_t t;

		shim_klds(klds, nklds_active);
		arm(n);
		dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV |
		    DTRACE_O_NOSYS, &err);
		if (dtp != NULL) {
			rc |= dtrace_lookup_by_name(dtp, "m32rel", "f", &sym,
			    NULL);
			rc |= dtrace_lookup_by_type(dtp, "childmod",
			    "struct child_t", &t);
			rc |= dtrace_lookup_by_name(dtp, "m64rel", "gdata", &sym,
			    NULL);
			{
				dtrace_syminfo_t si;
				dt_module_t *mm = dt_module_lookup_by_name(dtp,
				    "m64tie");

				/* An address lookup loads the module first
				 * (dtrace_update() unloads every module). */
				dtrace_update(dtp);
				mm = dt_module_lookup_by_name(dtp, "m64tie");
				if (mm != NULL)
					rc |= dtrace_lookup_by_addr(dtp,
					    mm->dm_text_va + 1, &sym, &si);
			}
		}
		arm(0);
		if (!fault_hit) {
			check(dtp != NULL && rc == 0, "module sweep unfaulted");
			done = 1;
		}
		if (dtp != NULL)
			dtrace_close(dtp);
	}
	printf("module fault sweep: %ld allocations, %d skipped\n", n - 1,
	    fault_skipped);

	/* Process CTF, extern declarations and new object scopes. */
	{
		pid_t pid = spawn("target");
		char obj[32];

		(void) snprintf(obj, sizeof (obj), "pid%d", (int)pid);
		for (n = 1, done = 0; !done && n < 20000; n++) {
			dtrace_hdl_t *dtp = mopen(0);
			dtrace_typeinfo_t t;
			int r1, r2, r3;

			arm(n);
			r1 = dtrace_lookup_by_type(dtp, obj, "struct tfoo", &t);
			r2 = dtrace_lookup_by_type(dtp, "brandnew", "int", &t);
			r3 = dtrace_program_strcompile(dtp,
			    "extern int xnew; BEGIN { trace(1); }",
			    DTRACE_PROBESPEC_NAME, 0, 0, NULL) == NULL;
			{
				GElf_Sym sy;
				dtrace_objinfo_t dto;
				char q[48];

				(void) snprintf(q, sizeof (q), "target`struct tfoo");
				r1 |= dtrace_lookup_by_type(dtp, obj, q, &t);
				r2 &= dtrace_lookup_by_name(dtp, "brandnew2", "x",
				    &sy, NULL);
				r2 &= dtrace_object_info(dtp, "brandnew3", &dto) ==
				    0 ? -1 : -1;
			}
			arm(0);
			if (!fault_hit) {
				check(r1 == 0 && r2 == -1 && r3 == 0,
				    "process sweep unfaulted");
				done = 1;
			} else {
				/* After a failed load the module is still the
				 * process's and loads once memory is back. */
				check(dtrace_lookup_by_type(dtp, obj,
				    "struct tfoo", &t) == 0,
				    "process CTF after fault %ld", n);
			}
			dtrace_close(dtp);
		}
		printf("process fault sweep: %ld allocations\n", n - 1);
		reap(pid);
	}
}
#endif

int
main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc != 3) {
		printf("FAIL usage\n");
		return (2);
	}
	moddir = argv[1];
	bind_shim();
	load_expect(argv[2]);
	check(neobjs == 21 && nesyms > 20, "expectations loaded (%d, %d)",
	    neobjs, nesyms);
	test_objects();
	test_symbols(0);
	test_types();
	test_pid_modules();
	test_process_ctf();
#ifdef WITH_FAULTS
	{
		static const char *const skip[] = { "dt_proc_init", NULL };
		/* libproc/librtld_db/libprocstat abort on allocation failure
		 * (assertions); they are outside this suite's files. */
		static const char *const libs[] = { "libproc.so",
		    "librtld_db.so", "libprocstat.so", NULL };

		fault_skip_fns = skip;
		fault_skip_libs = libs;
	}
	fault_sweep();
#endif
	exit(summary());
}
