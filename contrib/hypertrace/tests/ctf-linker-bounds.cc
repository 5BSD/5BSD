/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef enum { B_FALSE, B_TRUE } boolean_t;
typedef int64_t hrtime_t;

#include <dt_impl.h>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_inttab.h>
#include <dt_typefile.hh>
/* Exercise the actual built linker's relocation method, not a copy of its
 * arithmetic. Include all dependencies before exposing this private method
 * so the test macro cannot change any library header definitions. */
#define private public
#include <dt_hypertrace_linker.hh>
#undef private

/* Boundaries must preserve instructions when a USETX relocation is rejected. */
static void
test_usetx_preconditions(dtrace_hdl_t *dtp)
{
	using namespace dtrace;
	HyperTraceLinker linker(dtp, nullptr);
	dtrace_difo_t difo{};
	dif_instr_t instruction = DIF_INSTR_USETX(0, 7);
	difo.dtdo_buf = &instruction;
	difo.dtdo_len = 1;
	DFGNode node(dtp, nullptr, nullptr, &difo, nullptr, 0);
	assert(linker.patchUsetxDefs(nullptr) == E_HYPERTRACE_NONE);
	node.difo = nullptr;
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_NONE);
	node.difo = &difo;
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_NONE);
	ctf_membinfo_t member{};
	node.mip = &member;
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_NONE);
	assert(difo.dtdo_inthash == nullptr); /* Empty definition set. */
	node.usetxDefs.insert(&node);
	instruction = DIF_INSTR_NOP;
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_LINKING);
	assert(instruction == DIF_INSTR_NOP && !node.isRelocated);
	assert(difo.dtdo_inthash == nullptr);
	node.isRelocated = true;
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_NONE);
	assert(instruction == DIF_INSTR_NOP && difo.dtdo_inthash == nullptr);
	for (unsigned long offset : {0UL, 8UL, ULONG_MAX & ~7UL}) {
		node.isRelocated = false;
		instruction = DIF_INSTR_USETX(0, 7);
		member.ctm_offset = offset;
		assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_NONE);
		assert(DIF_INSTR_OP(instruction) == DIF_OP_SETX);
		assert(DIF_INSTR_RD(instruction) == 7 && node.isRelocated);
		uint64_t value = UINT64_MAX;
		assert(dt_inttab_size(difo.dtdo_inthash) == 1);
		dt_inttab_write(difo.dtdo_inthash, &value);
		assert(value == offset / 8);
		dt_inttab_destroy(difo.dtdo_inthash);
		difo.dtdo_inthash = nullptr;
	}
}

static void
test_typecast_symbol_bounds(dtrace_hdl_t *dtp)
{
	using namespace dtrace;
	HyperTraceLinker linker(dtp, nullptr);
	dif_instr_t instructions[3] = {DIF_INSTR_NOP, DIF_INSTR_NOP, DIF_INSTR_NOP};
	dtrace_difo_t difo{}, other{};
	difo.dtdo_buf = instructions;
	difo.dtdo_len = 3;
	DFGNode node(dtp, nullptr, nullptr, &difo, nullptr, 2);
	assert(linker.relocateDFGNode(&node, DTRACEACT_DIFEXPR, nullptr,
	    &other, nullptr) == E_HYPERTRACE_NONE);
	assert(!node.isRelocated && instructions[2] == DIF_INSTR_NOP);
	char terminated[] = "uintptr_t";
	char unterminated[] = {'x'};
	for (int mode = 0; mode < 5; mode++) {
		node.isRelocated = false;
		instructions[2] = DIF_INSTR_TYPECAST(mode == 3 ? 1 : 0, 1);
		difo.dtdo_symtab = mode == 0 ? nullptr : mode == 4 ? unterminated : terminated;
		difo.dtdo_symlen = mode == 1 ? 0 : mode >= 3 ? 1 : sizeof(terminated);
		int result = linker.relocateDFGNode(&node, DTRACEACT_DIFEXPR,
		    nullptr, &difo, nullptr);
		assert(result == (mode == 2 ? E_HYPERTRACE_NONE : E_HYPERTRACE_LINKING));
		assert(node.isRelocated == (mode == 2));
		if (mode != 2)
			assert(linker.getErrorMessage().find("symbol") != std::string::npos);
	}
	/* A leading type annotation is checked like any other (the linker no
	 * longer looks back for a sign-extension sequence to remove: that code
	 * is the cast itself). */
	for (unsigned index = 0; index < 2; index++) {
		DFGNode leading(dtp, nullptr, nullptr, &difo, nullptr, index);
		instructions[index] = DIF_INSTR_TYPECAST(0, 1);
		difo.dtdo_symtab = nullptr;
		difo.dtdo_symlen = 0;
		assert(linker.relocateDFGNode(&leading, DTRACEACT_DIFEXPR,
		    nullptr, &difo, nullptr) == E_HYPERTRACE_LINKING);
		instructions[index] = DIF_INSTR_TYPECAST(0, 1);
		difo.dtdo_symtab = terminated;
		difo.dtdo_symlen = sizeof(terminated);
		leading.isRelocated = false;
		assert(linker.relocateDFGNode(&leading, DTRACEACT_DIFEXPR,
		    nullptr, &difo, nullptr) == E_HYPERTRACE_NONE);
		assert(leading.isRelocated && instructions[index] == DIF_INSTR_NOP);
	}
}

/*
 * A load of an enum member (`((struct vm_exit *)arg1)->exitcode') is an
 * integer load of the enum's size, unsigned as dt_node_type_assign() types
 * it (libctf gives an enum no encoding).  The linker rejected it as "a load
 * of kind 8 is unsupported in DIF".
 */
static void
test_enum_member_load(dtrace_hdl_t *dtp)
{
	using namespace dtrace;
	int err = 0;
	ctf_file_t *fp = ctf_create(&err);
	assert(fp != nullptr);
	ctf_encoding_t ienc = {CTF_INT_SIGNED, 0, 32};
	ctf_id_t itype = ctf_add_integer(fp, CTF_ADD_ROOT, "int", &ienc);
	ctf_id_t etype = ctf_add_enum(fp, CTF_ADD_ROOT, "tf_exitcode");
	assert(itype != CTF_ERR && etype != CTF_ERR);
	assert(ctf_add_enumerator(fp, etype, "TF_EXIT_INOUT", 0) == 0);
	assert(ctf_add_enumerator(fp, etype, "TF_EXIT_BOGUS", 2) == 0);
	/* Member sizes come from committed types. */
	assert(ctf_update(fp) == 0);
	ctf_id_t stype = ctf_add_struct(fp, CTF_ADD_ROOT, "tf_exit");
	assert(stype != CTF_ERR);
	assert(ctf_add_member(fp, stype, "inst_length", itype) == 0);
	assert(ctf_add_member(fp, stype, "exitcode", etype) == 0);
	assert(ctf_update(fp) == 0);

	dt_module_t module{};
	module.dm_ctfp = fp;
	Typefile tf(dtp, &module, "enumfix");
	for (uint8_t op : {DIF_OP_ULOAD, DIF_OP_UULOAD}) {
		dif_instr_t insn = DIF_INSTR_LOAD(op, 2, 3);
		dtrace_difo_t difo{};
		difo.dtdo_buf = &insn;
		difo.dtdo_len = 1;
		DFGNode node(dtp, nullptr, nullptr, &difo, nullptr, 0);
		node.tf = &tf;
		node.ctfid = stype;
		node.sym = (char *)"exitcode";
		HyperTraceLinker linker(dtp, nullptr);
		int result = linker.relocateUloadOrAdd(&node);
		if (result != E_HYPERTRACE_NONE)
			fprintf(stderr, "enum member load: %s\n",
			    linker.getErrorMessage().c_str());
		assert(result == E_HYPERTRACE_NONE && node.isRelocated);
		assert(node.mip != nullptr && node.mip->ctm_offset == 32);
		assert(insn == (dif_instr_t)DIF_INSTR_LOAD(op == DIF_OP_ULOAD ?
		    DIF_OP_LDUW : DIF_OP_ULDUW, 2, 3));
		dt_free(dtp, node.mip);
	}
	module.dm_ctfp = nullptr;
	ctf_close(fp);
}

int
main(void)
{
	using namespace dtrace;
	auto *dtp = (dtrace_hdl_t *)calloc(1, sizeof(dtrace_hdl_t));
	assert(dtp != nullptr);
	test_usetx_preconditions(dtp);
	test_typecast_symbol_bounds(dtp);
	test_enum_member_load(dtp);
	dif_instr_t insn = DIF_INSTR_USETX(0, 1);
	dtrace_difo_t difo{};
	difo.dtdo_buf = &insn;
	difo.dtdo_len = 1;
	ctf_membinfo_t member{};
	member.ctm_offset = (65536UL + 17) * 8;
	DFGNode node(dtp, nullptr, nullptr, &difo, nullptr, 0);
	node.mip = &member;
	node.usetxDefs.insert(&node);
	HyperTraceLinker linker(dtp, nullptr);
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_NONE);
	assert(DIF_INSTR_OP(insn) == DIF_OP_SETX);
	uint64_t value = 0;
	assert(dt_inttab_size(difo.dtdo_inthash) == 1);
	dt_inttab_write(difo.dtdo_inthash, &value);
	assert(value == 65536UL + 17);
	dt_inttab_destroy(difo.dtdo_inthash);
	node.isRelocated = false;
	insn = DIF_INSTR_USETX(0, 1);
	difo.dtdo_inthash = nullptr;
	member.ctm_offset = 9;
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_LINKING);
	assert(insn == DIF_INSTR_USETX(0, 1));
	assert(difo.dtdo_inthash == nullptr);
	Typefile missing_type(dtp, nullptr, "missing");
	member.ctm_offset = 0;
	member.ctm_type = 1;
	insn = DIF_INSTR_FMT(DIF_OP_ULOAD, 0, 0, 1);
	node.tf = &missing_type;
	assert(linker.relocateUloadOrAdd(&node) == E_HYPERTRACE_LINKING);
	assert(insn == DIF_INSTR_FMT(DIF_OP_ULOAD, 0, 0, 1));
	node.tf = nullptr;
	assert(linker.relocateUloadOrAdd(&node) == E_HYPERTRACE_LINKING);
	assert(linker.getErrorMessage() == "missing CTF typefile for member load");
	assert(insn == DIF_INSTR_FMT(DIF_OP_ULOAD, 0, 0, 1));
	node.mip = nullptr;
	node.sym = nullptr;
	node.isRelocated = false;
	assert(linker.relocateUloadOrAdd(&node) == E_HYPERTRACE_LINKING);
	assert(linker.getErrorMessage() == "missing CTF member for load");
	assert(!node.isRelocated &&
	    insn == DIF_INSTR_FMT(DIF_OP_ULOAD, 0, 0, 1));
	insn = DIF_INSTR_FMT(DIF_OP_ADD, 0, 0, 1);
	assert(linker.relocateUloadOrAdd(&node) == E_HYPERTRACE_NONE);
	assert(node.isRelocated && insn == DIF_INSTR_FMT(DIF_OP_ADD, 0, 0, 1));
	insn = DIF_INSTR_FMT(DIF_OP_ULOAD, 0, 0, 1);
	node.sym = (char *)"missing_member";
	node.isRelocated = false;
	assert(linker.relocateUloadOrAdd(&node) == E_HYPERTRACE_LINKING);
	assert(linker.getErrorMessage() ==
	    "missing CTF typefile for member missing_member");
	assert(!node.isRelocated && node.mip == nullptr);
	node.tf = &missing_type;
	assert(linker.relocateUloadOrAdd(&node) == E_HYPERTRACE_LINKING);
	assert(!node.isRelocated && node.mip == nullptr);
	node.sym = nullptr;
	node.mip = &member;
	node.tf = &missing_type;
	linker.setErrorMessage("%s", "");
	assert(linker.getErrorMessage().empty());
	linker.setErrorMessage("%s", "a diagnostic longer than inline storage");
	assert(linker.getErrorMessage() ==
	    "a diagnostic longer than inline storage");
	difo.dtdo_inthash = dt_inttab_create(dtp);
	assert(difo.dtdo_inthash != nullptr);
	for (uint32_t i = 0; i < UINT16_MAX; i++)
		assert(dt_inttab_insert(difo.dtdo_inthash,
		    UINT64_C(0x100000000) + i, 0) == (int)i);
	/* The largest encodable index is valid; only the next one overflows. */
	member.ctm_offset = (UINT64_C(0x100000000) + UINT16_MAX) * 8;
	insn = DIF_INSTR_USETX(0, 1);
	node.isRelocated = false;
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_NONE);
	assert(insn == DIF_INSTR_SETX(UINT16_MAX, 1) && node.isRelocated);
	member.ctm_offset = 8;
	insn = DIF_INSTR_USETX(0, 1);
	node.isRelocated = false;
	assert(linker.patchUsetxDefs(&node) == E_HYPERTRACE_LINKING);
	assert(insn == DIF_INSTR_USETX(0, 1));
	dt_inttab_destroy(difo.dtdo_inthash);
	free(dtp);
	return (0);
}
