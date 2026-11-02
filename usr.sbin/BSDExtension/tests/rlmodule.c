/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Module fixtures for rootload_test: relocatable objects with the module
 * metadata linker set a kernel module carries (MODULE_VERSION, MODULE_DEPEND),
 * so the broker's libkldelf reader and the fake kernel resolve them as the
 * kernel linker would.  Compiled once per fixture (tests/Makefile):
 *   MOD, VERSION          the module's MODULE_VERSION;
 *   DEP, DEPMIN, DEPMAX   an optional MODULE_DEPEND;
 *   DEP2                  an optional second one (version 1).
 */

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/module.h>

#define	METADATA(sym, type, data, name)					\
	static struct mod_metadata sym = {				\
		MDT_STRUCT_VERSION, type, data, name			\
	};								\
	DATA_SET(modmetadata_set, sym)

static struct mod_version version = { VERSION };
METADATA(md_version, MDT_VERSION, &version, MOD);

#ifdef DEP
static struct mod_depend depend = { DEPMIN, DEPMIN, DEPMAX };
METADATA(md_depend, MDT_DEPEND, &depend, DEP);
#endif
#ifdef DEP2
static struct mod_depend depend2 = { 1, 1, 1 };
METADATA(md_depend2, MDT_DEPEND, &depend2, DEP2);
#endif
