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

#ifndef _DT_TYPEFILE_HH_
#define _DT_TYPEFILE_HH_

#include <dt_module.h>
#include <dtrace.h>

#ifndef __cplusplus
#error "File should only be included from C++"
#endif

#include <dt_cxxdefs.hh>

#include <string>

namespace dtrace {
struct struct_ctfinfo {
	Vec<ctf_id_t> ctf_types;
	ssize_t current_offs = 0;
};

class Typefile {
    private:
	UMap<ctf_id_t, Vec<ctf_id_t>> struct_info;

    public:
	dtrace_hdl_t *dtp = nullptr;
	dt_module_t *modhdl = nullptr;
	String modname;

    public:
	Typefile(dtrace_hdl_t *, dt_module_t *, String);
	Typefile(dtrace_hdl_t *, dt_module_t *, const char *);
	Typefile(dtrace_hdl_t *, dt_module_t *, char *);

	ctf_id_t getCtfID(const char *) const;
	char *getTypename(ctf_id_t, char *, size_t) const;
	ctf_id_t getReference(ctf_id_t) const;
	ssize_t getSize(ctf_id_t) const;
	const char *getErrMsg(void) const;
	ctf_file_t *getMembInfo(ctf_id_t, const char *, ctf_membinfo_t *) const;
	ctf_id_t getKind(ctf_id_t) const;
	ctf_id_t resolve(ctf_id_t);
	int getEncoding(ctf_id_t, ctf_encoding_t *);
	int typeIsCompatibleWith(ctf_id_t, const Typefile *, ctf_id_t);
	Vec<ctf_id_t> *buildStruct(ctf_id_t);
	ctf_id_t getMembCtfID(void *);
	ctf_file_t *getCtfPointer(void);
	ctf_arinfo_t *getArrayInfo(ctf_id_t);
	ctf_id_t stripReference(ctf_id_t &, size_t &);
	ctf_id_t stripTypedef(ctf_id_t &);

	const String &name() const;
	const std::optional<String> getTypename(ctf_id_t) const;
};

extern List<UPtr<Typefile>> typefiles;

void dt_typefile_openall(dtrace_hdl_t *);
Typefile *dt_typefile_first(void);
Typefile *dt_typefile_kernel(void);
Typefile *dt_typefile_D(void);
Typefile *dt_typefile_mod(const char *);

constexpr Typefile *
v2tf(void *tf)
{

	return (static_cast<Typefile *>(tf));
}

};

#endif
