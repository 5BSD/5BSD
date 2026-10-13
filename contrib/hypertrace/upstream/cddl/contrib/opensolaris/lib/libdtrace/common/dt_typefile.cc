/*-
 * Copyright (c) 2024 Domagoj Stolfa
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/linker.h>

#include <sys/ctf.h>

#include <sys/dtrace.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <execinfo.h>

#include <dtrace.h>
#include <dt_module.h>
#include <dt_typefile.hh>

namespace dtrace {

List<UPtr<Typefile>> typefiles;

Typefile::Typefile(dtrace_hdl_t *_dtp, dt_module_t *_mod, String _modname)
    : dtp(_dtp)
    , modhdl(_mod)
    , modname(_modname)
{
}

Typefile::Typefile(dtrace_hdl_t *_dtp, dt_module_t *_mod, const char *_modname)
    : dtp(_dtp)
    , modhdl(_mod)
    , modname(String(_modname))
{
}

Typefile::Typefile(dtrace_hdl_t *_dtp, dt_module_t *_mod, char *_modname)
    : dtp(_dtp)
    , modhdl(_mod)
    , modname(String(_modname))
{
}

void
dt_typefile_openall(dtrace_hdl_t *dtp)
{
	dt_module_t *mod;
	Typefile *typef;
	int kld;
	struct kld_file_stat kldinfo;


	mod = dt_module_lookup_by_name(dtp, "D");
	if (mod == nullptr)
		return;

	typefiles.push_back(std::make_unique<Typefile>(dtp, mod, "D"));
	if (typefiles.back() == nullptr)
		errx(EXIT_FAILURE, "dt_typefile_openall(): allocation failed");

	mod = dt_module_lookup_by_name(dtp, "C");
	if (mod == nullptr)
		return;

	typefiles.push_back(std::make_unique<Typefile>(dtp, mod, "C"));
	if (typefiles.back() == nullptr)
		errx(EXIT_FAILURE, "dt_typefile_openall(): allocation failed");

	for (kld = kldnext(0); kld > 0; kld = kldnext(kld)) {
		kldinfo.version = sizeof(kldinfo);
		if (kldstat(kld, &kldinfo) < 0)
			errx(EXIT_FAILURE, "kldstat() failed with: %s\n",
			    strerror(errno));

		mod = dt_module_lookup_by_name(dtp, kldinfo.name);
		if (mod == nullptr) {
			fprintf(stderr,
			    "dt_typefile_openall(): WARNING - "
			    "skipping module %s\n",
			    kldinfo.name);
			continue;
		}

		if (strcmp("kernel", kldinfo.name) == 0) {
			typefiles.push_front(
			    std::make_unique<Typefile>(dtp, mod, kldinfo.name));
			typef = typefiles.front().get();
		} else {
			typefiles.push_back(
			    std::make_unique<Typefile>(dtp, mod, kldinfo.name));
			typef = typefiles.back().get();
		}

		if (typef == nullptr)
			errx(EXIT_FAILURE,
			    "dt_typefile_openall(): allocation failed");
	}
}

ctf_id_t
Typefile::getCtfID(const char *type) const
{
	String t = String(type);
	ctf_file_t *ctfp;
	dtrace_typeinfo_t tip;
	const char *obj;
	String nonuser_type;
	static const String userland = "userland ";
	int rv;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (CTF_ERR);

	obj = nullptr;

	if (t.rfind(userland, 0) == 0) {
		nonuser_type = t.substr(userland.length());
	} else {
		nonuser_type = t;
	}

	if (this->modname == "C")
		obj = DTRACE_OBJ_CDEFS;
	else if (this->modname == "D")
		obj = DTRACE_OBJ_DDEFS;

	if (obj != nullptr) {
		rv = dtrace_lookup_by_type(this->dtp, obj, nonuser_type.c_str(),
		    &tip);
		if (rv != 0)
			return (CTF_ERR);

		return (tip.dtt_type);
	}

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (CTF_ERR);
	return (ctf_lookup_by_name(ctfp, nonuser_type.c_str()));
}

char *
Typefile::getTypename(ctf_id_t id, char *buf, size_t buf_size) const
{
	ctf_file_t *ctfp;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (nullptr);

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (nullptr);

	return (ctf_type_name(ctfp, id, buf, buf_size));
}

ctf_id_t
Typefile::getReference(ctf_id_t id) const
{
	ctf_file_t *ctfp;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (CTF_ERR);

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (CTF_ERR);

	return (ctf_type_reference(ctfp, id));
}

ssize_t
Typefile::getSize(ctf_id_t id) const
{
	ctf_file_t *ctfp;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (-1);

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (CTF_ERR);

	return (ctf_type_size(ctfp, id));
}

const char *
Typefile::getErrMsg(void) const
{
	ctf_file_t *ctfp;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return ("NOT INITIALIZED");

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return ("CTF file is nullptr");

	return (ctf_errmsg(ctf_errno(ctfp)));
}

ctf_file_t *
Typefile::getMembInfo(ctf_id_t type, const char *s, ctf_membinfo_t *mp) const
{
	ctf_file_t *ctfp;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (nullptr);

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (nullptr);

	while (ctf_type_kind(ctfp, type) == CTF_K_FORWARD) {
		char n[DT_TYPE_NAMELEN];
		dtrace_typeinfo_t dtt;

		auto rv = dtrace_lookup_by_type(this->dtp, DTRACE_OBJ_EVERY, n,
		    &dtt);
		if (ctf_type_name(ctfp, type, n, sizeof(n)) == nullptr ||
		    rv == -1 || (dtt.dtt_ctfp == ctfp && dtt.dtt_type == type))
			break; /* unable to improve our position */

		ctfp = dtt.dtt_ctfp;
		type = ctf_type_resolve(ctfp, dtt.dtt_type);
	}

	if (ctf_member_info(ctfp, type, s, mp) == CTF_ERR) {
		return (nullptr); /* ctf_errno is set for us */
	}

	return (ctfp);
}

ctf_id_t
Typefile::getKind(ctf_id_t type) const
{
	ctf_file_t *ctfp;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (CTF_ERR);

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (CTF_ERR);

	return (ctf_type_kind(ctfp, type));
}

Typefile *
dt_typefile_first(void)
{

	return (typefiles.front().get());
}

Typefile *
dt_typefile_kernel(void)
{
	dt_module_t *mod;

	for (auto &tf : typefiles) {
		if (tf->modname == "kernel") {
			mod = dt_module_lookup_by_name(tf->dtp, "kernel");
			assert(mod == tf->modhdl);
			return (tf.get());
		}
	}

	return (nullptr);
}

Typefile *
dt_typefile_D(void)
{
	dt_module_t *mod;

	for (auto &tf : typefiles) {
		if (tf->modname == "D") {
			mod = dt_module_lookup_by_name(tf->dtp, "D");
			assert(mod == tf->modhdl);
			return (tf.get());
		}
	}

	return (nullptr);
}

ctf_id_t
Typefile::resolve(ctf_id_t type)
{
	ctf_file_t *ctfp;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (CTF_ERR);

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (CTF_ERR);

	return (ctf_type_resolve(ctfp, type));
}

int
Typefile::getEncoding(ctf_id_t type, ctf_encoding_t *ep)
{
	ctf_file_t *ctfp;

	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (-1);

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (-1);

	return (ctf_type_encoding(ctfp, type, ep));
}

const String &
Typefile::name(void) const
{

	return (this->modname);
}

Typefile *
dt_typefile_mod(const char *mod)
{
	dt_module_t *_mod;

	if (mod == nullptr)
		return (nullptr);

	String mod_str = String(mod);
	for (auto &tf : typefiles) {
		if (tf->modname == mod_str) {
			_mod = dt_module_lookup_by_name(tf->dtp, mod);
			assert(_mod == tf->modhdl);
			return (tf.get());
		}
	}

	return (nullptr);
}

int
Typefile::typeIsCompatibleWith(ctf_id_t id, const Typefile *other,
    ctf_id_t other_id)
{
	ctf_file_t *ctfp, *ctfp_other;

	if (other == nullptr)
		return (0);

	ctfp = dt_module_getctf(this->dtp, this->modhdl);
	ctfp_other = dt_module_getctf(other->dtp, other->modhdl);

	if (ctfp == nullptr || ctfp_other == nullptr)
		return (0);

	return (ctf_type_compat(ctfp, id, ctfp_other, other_id));
}

static int
process_struct_member([[maybe_unused]] const char *name, ctf_id_t type,
    [[maybe_unused]] ulong_t offset, void *uarg)
{
	auto *types = static_cast<Vec<ctf_id_t> *>(uarg);
	assert(types != nullptr);

	types->push_back(type);
	return (0);
}

Vec<ctf_id_t> *
Typefile::buildStruct(ctf_id_t id)
{
	if (this->dtp == nullptr || this->modhdl == nullptr)
		return (nullptr);

	ctf_file_t *ctfp = dt_module_getctf(this->dtp, this->modhdl);
	if (ctfp == nullptr)
		return (nullptr);

	this->struct_info[id] = Vec<ctf_id_t>();
	auto *types = &this->struct_info[id];

	/*
	 * Populate the members of the struct.
	 */
	if (ctf_member_iter(ctfp, id, process_struct_member, types)) {
		this->struct_info.erase(id);
		return (nullptr);
	}

	return (&this->struct_info[id]);
}

ctf_file_t *
Typefile::getCtfPointer(void)
{

	return (dt_module_getctf(this->dtp, this->modhdl));
}

ctf_arinfo_t *
Typefile::getArrayInfo(ctf_id_t id)
{
	ctf_file_t *ctfp;
	ctf_arinfo_t *ai;

	ctfp = this->getCtfPointer();
	if (ctfp == nullptr)
		return (nullptr);

	ai = (ctf_arinfo_t *)malloc(sizeof(ctf_arinfo_t));
	if (ai == nullptr)
		return (nullptr);

	memset(ai, 0, sizeof(ctf_arinfo_t));
	if (ctf_array_info(ctfp, id, ai) == CTF_ERR) {
		free(ai);
		return (nullptr);
	}

	return (ai);
}

const std::optional<String>
Typefile::getTypename(ctf_id_t id) const
{
	char buf[DT_TYPE_NAMELEN] = { 0 };
	if (this->getTypename(id, buf, sizeof(buf)) != (char *)buf) {
		return (std::nullopt);
	}

	return (std::make_optional<String>(buf));
}

ctf_id_t
Typefile::stripReference(ctf_id_t &orig_id, size_t &n_stars)
{
	ctf_id_t kind;
	ctf_id_t id;
	size_t n_redirects;

	kind = getKind(orig_id);
	n_stars = 0;

	if (kind != CTF_K_TYPEDEF && kind != CTF_K_POINTER &&
	    kind != CTF_K_ARRAY)
		return (kind);

	id = orig_id;
	n_redirects = 0;

again:
	while (kind == CTF_K_TYPEDEF || kind == CTF_K_POINTER) {
		id = getReference(id);
		if (id == CTF_ERR) {
			fprintf(stderr,
			    "dt_typefile_reference() failed with: %s\n",
			    getErrMsg());
			return (CTF_ERR);
		}

		if (kind == CTF_K_POINTER)
			n_redirects++;

		kind = getKind(id);
	}

	assert(kind != CTF_K_TYPEDEF && kind != CTF_K_POINTER);
	if (kind == CTF_K_ARRAY) {
		ctf_arinfo_t *ai;

		ai = getArrayInfo(id);
		if (ai == nullptr)
			return (CTF_ERR);

		id = ai->ctr_contents;
		free(ai);

		n_redirects++;
		kind = getKind(id); /* update our kind */
		goto again;
	}

	n_stars = n_redirects;
	orig_id = id;
	return (kind);
}

ctf_id_t
Typefile::stripTypedef(ctf_id_t &orig_id)
{
	ctf_id_t kind;
	ctf_id_t id;

	kind = getKind(orig_id);

	if (kind != CTF_K_TYPEDEF)
		return (kind);

	id = orig_id;

	while (kind == CTF_K_TYPEDEF) {
		id = getReference(id);
		if (id == CTF_ERR) {
			fprintf(stderr,
			    "dt_typefile_reference() failed with: %s\n",
			    getErrMsg());
			return (CTF_ERR);
		}

		kind = getKind(id);
	}

	assert(kind != CTF_K_TYPEDEF);
	orig_id = id;

	return (kind);
}

}
