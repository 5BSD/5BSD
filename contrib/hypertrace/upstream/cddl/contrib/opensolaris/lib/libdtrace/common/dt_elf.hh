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

#ifndef _DT_ELF_HH_
#define _DT_ELF_HH_

#include <sys/stat.h>

#include <dt_cxxdefs.hh>
#include <dt_elf.h>
#include <dt_printf.h>
#include <dt_program.h>
#include <gelf.h>
#include <libelf.h>
#include <openssl/sha.h>
#include <dt_hypertrace.h>

#ifndef __cplusplus
#error "File should only be included from C++"
#endif

namespace dtrace {

using ChecksumArray = unsigned char[SHA256_DIGEST_LENGTH];
using ProgramIdentifier = char[DT_PROG_IDENTLEN];
class HyperTraceELFParser {
    public:
	HyperTraceELFParser(dtrace_hdl_t *, dtrace_prog_t *, int, const char *,
	    bool, uint32_t);
	~HyperTraceELFParser();

	const String &
	getErrorMessage()
	{
		return (errorMessage);
	}

    private:
	int elfHandle = -1;
	Elf *elfPtr = nullptr;
	const char *filename;
	struct stat elfFileStat;
	size_t idNameSize = 1;
	size_t idNameOffset = 0;
	char *idNameTable;
	dtrace_hdl_t *dtp = nullptr;
	dtrace_prog_t *program = nullptr;
	String errorMessage = "";
	dt_elf_ref_t firstActionSection = -1;
	dt_elf_ref_t lastActionSection = -1;
	dt_elf_actdesc_t *previousActDesc = nullptr;
	bool doResolve = true;
	uint32_t resolverFlags;
	dt_elf_actdesc_t *elfActionDesc = nullptr;

	static const dt_elf_ref_t kElfProgramSection;

	// dtrace_ecbdesc_t * | dt_elf_ref_t -> Elf_Scn * | dtrace_ecbdesc_t *
	ElfMap<dtrace_ecbdesc_t> ecbMap;
	// dtrace_actdesc_t * | dt_elf_ref_t -> Elf_Scn * | dtrace_actdesc_t *
	ElfMap<dtrace_actdesc_t> actionMap;

    private:
	void setErrorMessage(const char *, ...);

	Pair<size_t, int> createElfString(const char *);
	Pair<Elf_Scn *, int> createElfIntTab(dtrace_difo_t *);
	Pair<Elf_Scn *, int> createElfStrTab(dtrace_difo_t *);
	Pair<Elf_Scn *, int> createElfSymTab(dtrace_difo_t *);
	Pair<Elf_Scn *, int> createElfVarTab(dtrace_difo_t *);
	Pair<Elf_Scn *, int> createElfDifo(dtrace_difo_t *);
	Pair<Elf_Scn *, int> createElfEcbDesc(dtrace_stmtdesc_t *);
	Pair<Elf_Scn *, int> createElfAction(dtrace_actdesc_t *, dt_elf_ref_t);
	int createElfActions(dtrace_stmtdesc_t *, dt_elf_ref_t);
	Pair<dt_elf_ref_t, int> createElfStrData(void *);
	Pair<dt_elf_ref_t, int> createElfPfd(dt_pfargd_t *);
	Pair<dt_elf_ref_t, int> createElfFmtData(void *);
	Pair<Elf_Scn *, int> createElfStatement(dtrace_stmtdesc_t *,
	    dt_elf_stmt_t *);
	Pair<Elf_Scn *, int> createElfOptions(void);

    public:
	int createElf(int);
	Pair<dtrace_prog_t *, int> toProgram(dtrace_prog_t *);

    private:
	int parseOptions(dt_elf_ref_t, int, const String &);
	Pair<dt_pfargd_t *, int> parseElfPfd(dt_elf_ref_t, int, const String &);
	Pair<void *, int> parseFmtData(dt_elf_ref_t, int, const String &);
	Pair<void *, int> parseActionIdentifier(dt_elf_ref_t, int,
	    const String &);
	int addStatementToProgram(dtrace_stmtdesc_t *, dt_elf_stmt_t *, int,
	    const String &);
	void freeECB(dtrace_ecbdesc_t *);
	dtrace_stmtdesc_t *applyResolverFilter(dtrace_stmtdesc_t *,
	    dt_elf_stmt_t *);
	Pair<void *, int> parseElfTable(dt_elf_ref_t, int, const String &);
	Pair<dtrace_difo_t *, int> parseElfDifo(dt_elf_ref_t, int,
	    const String &);
	Pair<dt_elf_actdesc_t *, int> allocAction(dtrace_stmtdesc_t *,
	    dt_elf_ref_t, int, const String &);
	int allocActions(dtrace_stmtdesc_t *, dt_elf_stmt_t *, int,
	    const String &);
	Pair<dtrace_stmtdesc_t *, int> allocStatement(dt_elf_stmt_t *, int,
	    const String &);
	int parseStatements(dt_elf_ref_t, int, const String &);

	bool findIdentifierInCompileIdentifiers(ProgramIdentifier, bool &);
	Pair<int, int> verifyChecksum(ChecksumArray, String &);
	bool findIdentifierInCompileIdentifiers(unsigned char *, bool &);
	Pair<dtrace_ecbdesc_t *, int> parseElfEcbDesc(dt_elf_ref_t ecbref,
	    int newFD, const String &);

	template <typename T> inline Pair<T, int>
	makeError(T p, int e)
	{
		return (std::make_pair(p, e));
	}

	template <typename T> inline Pair<T, int>
	makeSuccess(T p)
	{
		return (std::make_pair(p, E_HYPERTRACE_NONE));
	}

	inline bool
	identsAreEqual(void *firstIdent, void *secondIdent)
	{
		return (memcmp(firstIdent, secondIdent, DT_PROG_IDENTLEN) == 0);
	}
};
}
#endif // _DT_ELF_HH_
