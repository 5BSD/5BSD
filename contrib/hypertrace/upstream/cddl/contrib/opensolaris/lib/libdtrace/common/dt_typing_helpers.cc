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

#include <dt_typing.hh>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_list.h>
#include <dt_linker_subr.hh>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_typefile.hh>
#include <dt_hypertrace_linker.hh>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include <dt_typing_helpers.hh>

namespace dtrace {
namespace impl {
static int
ctfTypeCompare(TypeInference *ti, USet<String> &processed_typenames,
    Typefile *_tf1, ctf_id_t _id1, Typefile *_tf2, ctf_id_t _id2)
{
	Typefile *tf1, *tf2;
	size_t n_stars1, n_stars2;
	ctf_id_t id1, id2, kind1, kind2, tmp, memb1, memb2;
	String type1_name, type2_name, memb1_name, memb2_name;

	assert(_tf1 != nullptr);
	assert(_tf2 != nullptr);

	/*
	 * If we're comparing the same type, it's just equal.
	 */
	if (_tf1 == _tf2 && _id1 == _id2)
		return (0);

	kind1 = _tf1->stripReference(id1, n_stars1);
	kind2 = _tf2->stripReference(id2, n_stars2);

	assert(kind1 != CTF_K_UNKNOWN);
	assert(kind2 != CTF_K_UNKNOWN);

	assert(kind1 != CTF_K_FUNCTION);
	assert(kind2 != CTF_K_FUNCTION);

	assert(kind1 != CTF_K_FLOAT);
	assert(kind2 != CTF_K_FLOAT);

	assert(kind1 < CTF_K_MAX);
	assert(kind2 < CTF_K_MAX);

	tf1 = kind1 == CTF_K_STRUCT ? _tf1 : _tf2;
	tf2 = kind1 == CTF_K_STRUCT ? _tf2 : _tf1;
	id1 = kind1 == CTF_K_STRUCT ? _id1 : _id2;
	id2 = kind1 == CTF_K_STRUCT ? _id2 : _id1;

	tmp = kind1;
	kind1 = tmp == CTF_K_STRUCT ? tmp : kind2;
	kind2 = tmp == CTF_K_STRUCT ? kind2 : tmp;

	auto opt = tf1->getTypename(id1);
	if (!opt.has_value()) {
		fprintf(stderr, "dt_typefile_typename() failed: %s\n",
		    tf1->getErrMsg());
		return (-1);
	}

	type1_name = std::move(opt.value());
	opt = tf2->getTypename(id2);
	if (!opt.has_value()) {
		fprintf(stderr, "dt_typefile_typename() failed: %s\n",
		    tf2->getErrMsg());
		return (-1);
	}

	type2_name = std::move(opt.value());

	/*
	 * Give integers some leeway.
	 */
	if (kind1 == CTF_K_INTEGER && kind2 == CTF_K_INTEGER) {
		if (tf1->typeIsCompatibleWith(id1, tf2, id2) == 0) {
			fprintf(stderr,
			    "%s(): %s and %s are incompatible integers\n",
			    __func__, type1_name.c_str(), type2_name.c_str());
			return (-1);
		}

		return (0);
	}

	/*
	 * Names must match
	 */
	if (type1_name != type2_name) {
		fprintf(stderr, "%s(): comparison not possible: %s != %s\n",
		    __func__, type1_name.c_str(), type2_name.c_str());
		return (-1);
	}

	if (kind1 == CTF_K_UNION || kind1 == CTF_K_ENUM ||
	    kind1 == CTF_K_FORWARD) {
		if (tf1->typeIsCompatibleWith(id1, tf2, id2) == 0) {
			fprintf(stderr,
			    "dt_typefile_compat(): %s is not "
			    "compatible with %s\n",
			    type1_name.c_str(), type2_name.c_str());
			return (-1);
		}

		return (0);
	}

	if (kind1 == CTF_K_STRUCT) {
		auto *s1 = tf1->buildStruct(id1);
		if (s1 == nullptr) {
			fprintf(stderr,
			    "dt_typefile_buildup_struct(%s) "
			    "failed for %s: %s\n",
			    tf1->name().c_str(), type1_name.c_str(),
			    tf1->getErrMsg());
			return (-1);
		}

		auto *s2 = tf2->buildStruct(id2);
		if (s2 == nullptr) {
			fprintf(stderr,
			    "dt_typefile_buildup_struct(%s) "
			    "failed for %s: %s\n",
			    tf2->name().c_str(), type2_name.c_str(),
			    tf2->getErrMsg());
			return (-1);
		}

		Vec<ctf_id_t>::iterator it1, it2;
		/*
		 * Go over each member and ensure that if both exist, they are
		 * pointwise equal. We don't accept *any* variety between them.
		 */
		for (it1 = s1->begin(), it2 = s2->begin();
		     it1 != s1->end() && it2 != s2->end(); ++it1, ++it2) {
			memb1 = *it1;
			memb2 = *it2;

			opt = tf1->getTypename(memb1);
			if (!opt.has_value()) {
				fprintf(stderr,
				    "dt_typefile_typename() failed: %s\n",
				    tf1->getErrMsg());
				return (-1);
			}

			memb1_name = std::move(opt.value());
			opt = tf2->getTypename(memb2);
			if (!opt.has_value()) {
				fprintf(stderr,
				    "dt_typefile_typename() failed: %s\n",
				    tf2->getErrMsg());
				return (-1);
			}

			memb2_name = std::move(opt.value());

			if (processed_typenames.contains(memb1_name))
				continue;

			if (impl::ctfTypeCompare(ti, processed_typenames, tf1,
			    memb1, tf2, memb2)) {
				fprintf(stderr,
				    "comparison between %s and %s failed\n",
				    memb1_name.c_str(), memb2_name.c_str());
				return (-1);
			}

			processed_typenames.insert(memb1_name);
		}

		assert(it1 == s1->end() || it2 == s2->end());

		if (memb1 != memb2) {
			fprintf(stderr,
			    "structures %s (%s) and %s (%s) "
			    "don't match\n",
			    type1_name.c_str(), tf1->name().c_str(),
			    type2_name.c_str(), tf2->name().c_str());
			return (-1);
		}
	}

	return (0);
}
}

int
TypeInference::ctfTypeCompare(Typefile *tf1, ctf_id_t id1, Typefile *tf2,
    ctf_id_t id2)
{
	USet<String> processed_typenames;
	return (impl::ctfTypeCompare(this, processed_typenames, tf1, id1, tf2,
	    id2));
}

int
dt_typecheck_string(dtrace_hdl_t *dtp, int t1, int t2, ctf_id_t c1, ctf_id_t c2,
    Typefile *tf1, Typefile *tf2)
{
	if (t1 == DIF_TYPE_STRING && t2 == DIF_TYPE_CTF) {
		dt_module_t *mod = tf2->modhdl;
		return (c2 == dtp->dt_type_str && mod == dtp->dt_ddefs);
	} else if (t1 == DIF_TYPE_CTF && t2 == DIF_TYPE_STRING) {
		return (dt_typecheck_string(dtp, t2, t1, c2, c1, tf2, tf1));
	}

	return (t1 == DIF_TYPE_STRING && t2 == DIF_TYPE_STRING);
}

int
dt_typecheck_stringiv(dtrace_hdl_t *dtp, DFGNode *n, dtrace_difv_t *dv)
{

	return (dt_typecheck_string(dtp, n->dType, dv->dtdv_type.dtdt_kind,
	    n->ctfid, dv->dtdv_ctfid, n->tf, v2tf(dv->dtdv_tf)));
}

int
dt_typecheck_stringii(dtrace_hdl_t *dtp, DFGNode *n1, DFGNode *n2)
{

	return (dt_typecheck_string(dtp, n1->dType, n2->dType,
	    n1->ctfid, n2->ctfid, n1->tf, n2->tf));
}

/*
 * dt_get_class() takes in a buffer containing the type name and returns
 * the internal DTrace class it belongs to (DTC_INT, DTC_BOTTOM, DTC_STRUCT).
 */
int
dt_get_class(Typefile *tf, ctf_id_t id, int follow)
{
	ctf_id_t ot, k, new_id;
	int typeclass;
	char buf[DT_TYPE_NAMELEN];
	Typefile *typef;

	ot = -1;
	k = 0;

	/* ignore any errors here. */
	tf->getTypename(id, buf, sizeof(buf));

	do {

		if ((k = tf->getKind(id)) == CTF_ERR)
			return (DTC_BOTTOM);

		if (id == ot)
			break;

		ot = id;
	} while (((id = tf->getReference(id)) != CTF_ERR));

	if (k == CTF_K_INTEGER)
		return (DTC_INT);

	if (k == CTF_K_STRUCT)
		return (DTC_STRUCT);

	if (k == CTF_K_UNION)
		return (DTC_UNION);

	if (k == CTF_K_ENUM)
		return (DTC_ENUM);

	if (k == CTF_K_ARRAY) {
		ctf_arinfo_t *ai;
		ctf_id_t src_type;

		ai = tf->getArrayInfo(ot);
		if (ai == nullptr)
			return (DTC_BOTTOM);

		src_type = ai->ctr_contents;
		free(ai);

		return (dt_get_class(tf, src_type, 1));
	}

	if (k == CTF_K_FORWARD) {
		ctf_file_t *parent, *current;
		if (!follow)
			return (DTC_FORWARD);

		parent = ctf_parent_file(tf->getCtfPointer());
		if (parent == nullptr)
			return (DTC_FORWARD);

		if (id == CTF_ERR)
			id = ot;

		typef = nullptr;

		/* follow the list of typefiles until we find the right one */
		for (auto &t : typefiles) {
			current = t->getCtfPointer();
			if (current == parent) {
				typef = t.get();
				break;
			}

			typeclass = dt_get_class(t.get(), t->getCtfID(buf), 0);
			if (typeclass == DTC_INT || typeclass == DTC_STRUCT)
				return (typeclass);
		}

		if (typef == nullptr)
			return (DTC_FORWARD);

		new_id = typef->getCtfID(buf);
		if (new_id == CTF_ERR)
			return (DTC_FORWARD);
		typeclass = dt_get_class(typef, new_id, 0);
		return (typeclass);
	}

	return (DTC_BOTTOM);
}

/*
 * typeCompare() takes in two IFG nodes and "compares" their types.
 * Specifically, BOTTOM is the smallest element and no matter what it is
 * compared to, it is smaller than it (reflexivity applies). By convention,
 * we check dr1 for a BOTTOM type first and return dn2 if dr1 is BOTTOM
 * regardless of what dn2 is (could be BOTTOM). Both STRUCT and STRING are
 * considered to be greater than INT (because in DIF when we are adding an
 * integer onto a struct pointer or a string, we still expect to use it as
 * a string or a structure, rather than as a number).
 */
int
TypeInference::typeCompare(DFGNode *dn1, DFGNode *dn2)
{
	String t1, t2;
	int class1, class2;

	class1 = 0;
	class2 = 0;

	if (dn1->dType == DIF_TYPE_BOTTOM &&
	    dn2->dType == DIF_TYPE_BOTTOM)
		dt_set_progerr(dtp, pgp, "both types are bottom");

	assert(dn1->dType != DIF_TYPE_BOTTOM ||
	    dn2->dType != DIF_TYPE_BOTTOM);

	if (dn1->dType == DIF_TYPE_BOTTOM)
		return (2);

	if (dn2->dType == DIF_TYPE_BOTTOM)
		return (1);

	assert(dn1->dType != DIF_TYPE_NONE);
	assert(dn2->dType != DIF_TYPE_NONE);

	if (dn1->dType == DIF_TYPE_CTF) {
		auto opt = dn1->tf->getTypename(dn1->ctfid);
		if (!opt.has_value()) {
			dt_set_progerr(dtp, pgp,
			    "dt_type_compare(): failed at getting type "
			    "name %ld: %s",
			    dn1->ctfid, dn1->tf->getErrMsg());
		}

		t1 = std::move(opt.value());
	}

	if (dn2->dType == DIF_TYPE_CTF) {
		auto opt = dn2->tf->getTypename(dn2->ctfid);
		if (!opt.has_value()) {
			dt_set_progerr(dtp, pgp,
			    "dt_type_compare(): failed at getting type "
			    "name %ld: %s",
			    dn2->ctfid, dn2->tf->getErrMsg());
		}

		t2 = std::move(opt.value());
	}

	class1 = dn1->dType == DIF_TYPE_CTF ?
	    dt_get_class(dn1->tf, dn1->ctfid, 1) :
	    DTC_STRING;
	class2 = dn2->dType == DIF_TYPE_CTF ?
	    dt_get_class(dn2->tf, dn2->ctfid, 1) :
	    DTC_STRING;

	if (class1 == DTC_BOTTOM)
		dt_set_progerr(dtp, pgp,
		    "dt_type_compare(): class1 is bottom because of %s",
		    t1.c_str());

	if (class2 == DTC_BOTTOM)
		dt_set_progerr(dtp, pgp,
		    "dt_type_compare(): class2 is bottom because of %s",
		    t2.c_str());

	if (class1 == DTC_STRING && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_STRUCT && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_UNION && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_FORWARD && class2 == DTC_INT)
		return (1);

	if ((class1 == DTC_ENUM && class2 == DTC_ENUM) ||
	    (class1 == DTC_INT && class2 == DTC_ENUM)  ||
	    (class1 == DTC_ENUM && class2 == DTC_INT))
		return (1);

	if (class1 == DTC_INT &&
	    (class2 == DTC_STRUCT || class2 == DTC_STRING ||
	    class2 == DTC_FORWARD || class2 == DTC_UNION))
		return (2);

	/*
	 * If the types are of the same class, we return the the first type
	 * by convention.
	 */
	if (class1 == DTC_INT && class2 == DTC_INT)
		return (1);

	return (-1);
}

Typefile *
HyperTraceLinker::getTypenameChecked(DFGNode *n, Vec<Typefile *> &tfs,
    char *buf, size_t bufsize, const String &loc)
{
	if (std::find(tfs.begin(), tfs.end(), n->tf) == tfs.end())
		dt_set_progerr(dtp, pgp,
		    "%s: node %zu' could not find typefile '%s'", loc.c_str(),
		    n->uidx, n->tf->name().c_str());

	if (n->tf->getTypename(n->ctfid, buf, bufsize) != buf)
		dt_set_progerr(dtp, pgp,
		    "%s: (%zu) failed getting type name %ld: %s", loc.c_str(),
		    n->uidx, n->ctfid, n->tf->getErrMsg());

	return (n->tf);
}

ctf_id_t
dt_autoresolve_ctfid(const char *mod, const char *resolved_type,
    Typefile **tfp)
{
	Typefile *tf;
	ctf_id_t ctfid;

	tf = nullptr;
	ctfid = CTF_ERR;

	/*
	 * Try by module first.
	 */
	if (strcmp(mod, "freebsd") == 0)
		tf = dt_typefile_kernel();
	else
		tf = dt_typefile_mod(mod);

	if (tf != nullptr)
		ctfid = tf->getCtfID(resolved_type);

	if (tf == nullptr || ctfid == CTF_ERR) {
		/*
		 * FIXME: This probably doesn't match what libdtrace currently
		 * does with modules.
		 */
		for (auto &t : typefiles) {
			ctfid = t->getCtfID(resolved_type);
			if (ctfid != CTF_ERR) {
				tf = t.get();
				break;
			}
		}
	}

	*tfp = tf;
	return (ctfid);
}

}
