/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { B_FALSE, B_TRUE } boolean_t;
typedef int64_t hrtime_t;

#include <dt_impl.h>
#include <dt_printf.h>
#include <dt_program.h>

extern int dt_prog_verify_difo(void *, dtrace_difo_t *, dtrace_difo_t *,
    char *, char *);

static void
verify_relocations(dtrace_hdl_t *dtp)
{
	dif_instr_t base_insns[2], guest_insns[2];
	uint64_t guest_integers[] = { 9, 10 };
	dtrace_difo_t base = {}, guest = {};
	void *ctx = dt_verictx_init(dtp);
	char target[] = "test:::probe";

	assert(ctx != NULL);
	base.dtdo_buf = base_insns;
	guest.dtdo_buf = guest_insns;
	guest.dtdo_inttab = guest_integers;
	guest.dtdo_intlen = 1;
	base.dtdo_len = guest.dtdo_len = 1;
	base_insns[0] = DIF_INSTR_USETX(7, 3);
	guest_insns[0] = DIF_INSTR_SETX(0, 3);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest.dtdo_intlen = 2;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_intlen = (uint_t)UINT16_MAX + 2;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_intlen = 2;
	base.dtdo_len = guest.dtdo_len = 2;
	base_insns[1] = DIF_INSTR_USETX(8, 4);
	guest_insns[1] = DIF_INSTR_SETX(1, 4);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest.dtdo_intlen = 1;
	guest_insns[1] = DIF_INSTR_SETX(0, 4);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest.dtdo_intlen = 2;
	guest_insns[1] = DIF_INSTR_SETX(0, 4);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base.dtdo_len = guest.dtdo_len = 1;
	guest.dtdo_intlen = 1;
	guest_insns[0] = DIF_INSTR_SETX(1, 3);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_insns[0] = DIF_INSTR_SETX(0, 4);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_len = 0;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_len = 1;
	guest.dtdo_buf = NULL;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_buf = guest_insns;
	guest.dtdo_varlen = 1;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_varlen = 0;
	guest.dtdo_intlen = 0;
	base_insns[0] = DIF_INSTR_FMT(DIF_OP_ULOAD, 2, 1, 3);
	guest_insns[0] = DIF_INSTR_LOAD(DIF_OP_LDX, 2, 3);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest_insns[0] = DIF_INSTR_LOAD(DIF_OP_LDX, 4, 3);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_insns[0] = DIF_INSTR_LOAD(DIF_OP_LDX, 2, 4);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_insns[0] = DIF_INSTR_FMT(DIF_OP_NOP, 1, 0, 0);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base.dtdo_len = guest.dtdo_len = 2;
	base_insns[1] = guest_insns[1] = DIF_INSTR_RET(3);
	guest_insns[0] = DIF_INSTR_NOP;
	guest.dtdo_rtype.dtdt_flags = DIF_TF_BYREF;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base.dtdo_rtype.dtdt_flags = DIF_TF_BYREF;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest.dtdo_rtype.dtdt_flags = 0;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_rtype.dtdt_flags = DIF_TF_BYUREF;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base.dtdo_rtype.dtdt_flags = DIF_TF_BYUREF;
	base_insns[1] = guest_insns[1] = DIF_INSTR_RET(2);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base_insns[1] = guest_insns[1] = DIF_INSTR_RET(3);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	base_insns[0] = DIF_INSTR_FMT(DIF_OP_UULOAD, 2, 1, 3);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest.dtdo_rtype.dtdt_flags = 0;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base.dtdo_rtype.dtdt_flags = 0;
	guest.dtdo_rtype.dtdt_flags = 0;
	base.dtdo_len = guest.dtdo_len = 1;
	base_insns[0] = DIF_INSTR_TYPECAST(7, 3);
	guest_insns[0] = DIF_INSTR_FMT(DIF_OP_NOP, 0, 0, 1);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_insns[0] = DIF_INSTR_NOP;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	base.dtdo_inttab = guest_integers;
	base.dtdo_intlen = guest.dtdo_intlen = 1;
	const uint8_t exact_ops[] = {
	    DIF_OP_SLL, DIF_OP_SRA, DIF_OP_SETX };
	for (size_t op = 0; op < sizeof(exact_ops) / sizeof(exact_ops[0]);
	    op++) {
		base_insns[0] = DIF_INSTR_FMT(exact_ops[op], 1, 2, 3);
		guest_insns[0] = base_insns[0];
		assert(dt_prog_verify_difo(ctx, &base, &guest,
		    target, target) == 0);
		guest_insns[0] = DIF_INSTR_NOP;
		assert(dt_prog_verify_difo(ctx, &base, &guest,
		    target, target) != 0);
	}
	base_insns[0] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
	    DIF_TYPE_STRING, 0, 1);
	guest_insns[0] = base_insns[0];
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest_insns[0] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
	    DIF_TYPE_CTF, 0, 1);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base_insns[0] = guest_insns[0];
	guest_insns[0] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
	    DIF_TYPE_STRING, 0, 1);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base_insns[0] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
	    DIF_TYPE_BOTTOM, 0, 1);
	guest_insns[0] = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
	    DIF_TYPE_CTF, 0, 1);
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	dt_verictx_teardown(ctx);
}

static void
verify_difo_metadata(dtrace_hdl_t *dtp)
{
	dif_instr_t base_instruction = DIF_INSTR_USETX(7, 3);
	dif_instr_t guest_instruction = DIF_INSTR_SETX(1, 3);
	uint64_t base_ints[] = { 7 }, guest_ints[] = { 7, 9 };
	char base_str[] = "abc", guest_str[] = "abc";
	char base_sym[] = "member", guest_sym[] = "member";
	dtrace_difv_t base_var = {}, guest_var = {};
	dtrace_difo_t base = {}, guest = {};
	void *ctx = dt_verictx_init(dtp);
	char target[] = "test:::metadata";

	assert(ctx != NULL);
	base.dtdo_buf = &base_instruction;
	guest.dtdo_buf = &guest_instruction;
	base.dtdo_len = guest.dtdo_len = 1;
	base.dtdo_inttab = base_ints;
	guest.dtdo_inttab = guest_ints;
	base.dtdo_intlen = 1;
	guest.dtdo_intlen = 2;
	base.dtdo_strtab = base_str;
	guest.dtdo_strtab = guest_str;
	base.dtdo_strlen = guest.dtdo_strlen = sizeof(base_str);
	base.dtdo_symtab = base_sym;
	guest.dtdo_symtab = guest_sym;
	base.dtdo_symlen = guest.dtdo_symlen = sizeof(base_sym);
	base_var.dtdv_id = guest_var.dtdv_id = 17;
	base.dtdo_vartab = &base_var;
	guest.dtdo_vartab = &guest_var;
	base.dtdo_varlen = guest.dtdo_varlen = 1;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest_ints[0] = 8;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_ints[0] = 7;
	guest_str[0] = 'x';
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_str[0] = 'a';
	guest_sym[0] = 'x';
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_sym[0] = 'm';
	guest_var.dtdv_id = 18;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_var.dtdv_id = 17;
	guest.dtdo_destructive = 1;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_destructive = 0;
	guest_var.dtdv_type.dtdt_kind = DIF_TYPE_STRING;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_var.dtdv_type.dtdt_kind = base_var.dtdv_type.dtdt_kind;
	guest_var.dtdv_type.dtdt_ckind = 1;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_var.dtdv_type.dtdt_ckind = base_var.dtdv_type.dtdt_ckind;
	guest_var.dtdv_type.dtdt_flags = DIF_TF_BYREF;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_var.dtdv_type.dtdt_flags = base_var.dtdv_type.dtdt_flags;
	guest_var.dtdv_type.dtdt_kind = 0x7f;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_var.dtdv_type.dtdt_kind = base_var.dtdv_type.dtdt_kind;
	guest_var.dtdv_type.dtdt_flags = 0x80;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_var.dtdv_type.dtdt_flags = base_var.dtdv_type.dtdt_flags;
	guest_var.dtdv_type.dtdt_pad = 1;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest_var.dtdv_type.dtdt_pad = 0;
	guest.dtdo_rtype.dtdt_kind = DIF_TYPE_STRING;
	guest.dtdo_rtype.dtdt_size = 13;
	guest.dtdo_buf = NULL;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	assert(guest.dtdo_rtype.dtdt_size == 13);
	guest.dtdo_buf = &guest_instruction;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	base.dtdo_rtype.dtdt_kind = DIF_TYPE_STRING;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest.dtdo_rtype.dtdt_flags = DIF_TF_BYREF;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_rtype.dtdt_flags = 0;
	base.dtdo_rtype.dtdt_kind = DIF_TYPE_BOTTOM;
	guest.dtdo_rtype.dtdt_kind = DIF_TYPE_CTF;
	/* A register-sized CTF result of a BOTTOM base is an integer, enum,
	 * float or pointer (dtdt_ckind is a CTF kind). */
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_rtype.dtdt_ckind = CTF_K_INTEGER;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	base.dtdo_rtype.dtdt_kind = DIF_TYPE_CTF;
	guest.dtdo_rtype.dtdt_kind = DIF_TYPE_CTF;
	base.dtdo_rtype.dtdt_size = guest.dtdo_rtype.dtdt_size;
	base.dtdo_rtype.dtdt_ckind = 7;
	guest.dtdo_rtype.dtdt_ckind = 8;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_rtype.dtdt_ckind = 7;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	guest.dtdo_rtype.dtdt_size++;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_rtype.dtdt_size--;
	base.dtdo_rtype.dtdt_kind = DIF_TYPE_STRING;
	guest.dtdo_rtype.dtdt_kind = DIF_TYPE_STRING;
	guest.dtdo_rtype.dtdt_kind = 0x7f;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_rtype.dtdt_kind = DIF_TYPE_STRING;
	guest.dtdo_rtype.dtdt_flags = 0x80;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_rtype.dtdt_flags = 0;
	guest.dtdo_rtype.dtdt_pad = 1;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) != 0);
	guest.dtdo_rtype.dtdt_pad = 0;
	assert(dt_prog_verify_difo(ctx, &base, &guest, target, target) == 0);
	dt_verictx_teardown(ctx);
}

static void
verify_failed_difo_program(dtrace_hdl_t *dtp)
{
	dtrace_prog_t *base = dt_program_create(dtp);
	dtrace_prog_t *guest = dt_program_create(dtp);
	dtrace_probedesc_t probe = {};
	dtrace_ecbdesc_t *base_ecb, *guest_ecb;
	dtrace_stmtdesc_t *stmt;
	dtrace_difo_t *base_difo, *guest_difo;
	dtrace_difv_t probe_base_var = {}, probe_new_var = {};
	dtrace_difo_t probe_base = {}, probe_new = {};
	dif_instr_t instruction = DIF_INSTR_NOP;
	void *ctx = dt_verictx_init(dtp);
	char target[] = "test:::difo";

	assert(base != NULL && guest != NULL && ctx != NULL);
	strcpy(probe.dtpd_provider, "test");
	strcpy(probe.dtpd_name, "difo");
	base_ecb = dt_ecbdesc_create(dtp, &probe);
	guest_ecb = dt_ecbdesc_create(dtp, &probe);
	assert(base_ecb != NULL && guest_ecb != NULL);
	base_difo = calloc(1, sizeof(*base_difo));
	guest_difo = calloc(1, sizeof(*guest_difo));
	assert(base_difo != NULL && guest_difo != NULL);
	dtrace_difo_t *difos[] = {base_difo, guest_difo};
	for (size_t i = 0; i < 2; i++) {
		dtrace_difo_t *difo = difos[i];
		difo->dtdo_buf = calloc(1, sizeof(dif_instr_t));
		difo->dtdo_vartab = calloc(1, sizeof(dtrace_difv_t));
		assert(difo->dtdo_buf != NULL && difo->dtdo_vartab != NULL);
		difo->dtdo_buf[0] = instruction;
		difo->dtdo_len = difo->dtdo_varlen = 1;
		difo->dtdo_vartab[0].dtdv_id = 17;
		difo->dtdo_vartab[0].dtdv_kind = DIFV_KIND_SCALAR;
		difo->dtdo_vartab[0].dtdv_type.dtdt_kind = DIF_TYPE_CTF;
	}
	base_difo->dtdo_vartab[0].dtdv_type.dtdt_size = 4;
	guest_difo->dtdo_vartab[0].dtdv_type.dtdt_size = 8;
	base_ecb->dted_pred.dtpdd_difo = base_difo;
	guest_ecb->dted_pred.dtpdd_difo = guest_difo;
	stmt = dtrace_stmt_create(dtp, base_ecb);
	assert(stmt != NULL && dtrace_stmt_add(dtp, base, stmt) == 0);
	stmt = dtrace_stmt_create(dtp, guest_ecb);
	assert(stmt != NULL && dtrace_stmt_add(dtp, guest, stmt) == 0);
	void *accepted_ctx = dt_verictx_init(dtp);
	size_t mark;
	assert(accepted_ctx != NULL);
	mark = dt_verictx_mark(accepted_ctx);
	assert(mark == 0 &&
	    dt_prog_verify(accepted_ctx, base, guest) == 0 &&
	    dt_verictx_mark(accepted_ctx) == 1 &&
	    base_difo->dtdo_vartab[0].dtdv_type.dtdt_size == 4 &&
	    guest_difo->dtdo_vartab[0].dtdv_type.dtdt_size == 8);
	stmt = dtrace_stmt_create(dtp, guest_ecb);
	assert(stmt != NULL && dtrace_stmt_add(dtp, guest, stmt) == 0);
	assert(dt_prog_verify(ctx, base, guest) != 0);
	assert(base_difo->dtdo_vartab[0].dtdv_type.dtdt_size == 4 &&
	    guest_difo->dtdo_vartab[0].dtdv_type.dtdt_size == 8);
	/* If the failed program remained in the context, this conflicting
	 * variable type would make an otherwise valid DIFO fail. */
	probe_base_var.dtdv_id = probe_new_var.dtdv_id = 17;
	probe_base_var.dtdv_kind = probe_new_var.dtdv_kind = DIFV_KIND_SCALAR;
	probe_base_var.dtdv_type.dtdt_kind =
	    probe_new_var.dtdv_type.dtdt_kind = DIF_TYPE_STRING;
	probe_base.dtdo_buf = probe_new.dtdo_buf = &instruction;
	probe_base.dtdo_vartab = &probe_base_var;
	probe_new.dtdo_vartab = &probe_new_var;
	probe_base.dtdo_len = probe_new.dtdo_len = 1;
	probe_base.dtdo_varlen = probe_new.dtdo_varlen = 1;
	assert(dt_prog_verify_difo(accepted_ctx, &probe_base, &probe_new,
	    target, target) != 0);
	dt_verictx_rewind(accepted_ctx, mark);
	assert(dt_verictx_mark(accepted_ctx) == mark &&
	    dt_prog_verify_difo(accepted_ctx, &probe_base, &probe_new,
	    target, target) == 0);
	dt_verictx_teardown(accepted_ctx);
	assert(dt_prog_verify_difo(ctx, &probe_base, &probe_new,
	    target, target) == 0);
	dt_verictx_teardown(ctx);
	dt_ecbdesc_release(dtp, base_ecb);
	dt_ecbdesc_release(dtp, guest_ecb);
	dt_program_destroy(dtp, guest);
	dt_program_destroy(dtp, base);
}

static void
verify_program_shape(dtrace_hdl_t *dtp)
{
	dtrace_prog_t *base = dt_program_create(dtp);
	dtrace_prog_t *guest = dt_program_create(dtp);
	dtrace_prog_t *guest_success = dt_program_create(dtp);
	dtrace_prog_t *empty = dt_program_create(dtp);
	dtrace_probedesc_t probe = {};
	dtrace_ecbdesc_t *ecb;
	dtrace_stmtdesc_t *stmt;
	dtrace_stmtdesc_t *base_first, *guest_first;
	dt_pfargv_t *base_fmt, *guest_fmt, *copied;
	dt_pfargd_t *prefix;
	void *ctx = dt_verictx_init(dtp);

	assert(base != NULL && guest != NULL && guest_success != NULL &&
	    empty != NULL && ctx != NULL);
	strcpy(probe.dtpd_provider, "test");
	strcpy(probe.dtpd_name, "probe");
	ecb = dt_ecbdesc_create(dtp, &probe);
	assert(ecb != NULL);
	stmt = dtrace_stmt_create(dtp, ecb);
	assert(stmt != NULL && dtrace_stmt_add(dtp, base, stmt) == 0);
	base_first = stmt;
	stmt = dtrace_stmt_create(dtp, ecb);
	assert(stmt != NULL && dtrace_stmt_add(dtp, guest, stmt) == 0);
	guest_first = stmt;
	assert(dt_prog_verify(ctx, base, guest) == 0);
	/* A guest's enabled-probe list is consumed by VPROBE_CREATE. It must
	 * describe probes covered by the verified source statements. */
	dtrace_probedesc_t enabled = probe;
	enabled.dtpd_id = 73;
	guest->dp_neprobes = 1;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest->dp_eprobes = &enabled;
	assert(dt_prog_verify(ctx, base, guest) == 0);
	strcpy(ecb->dted_probe.dtpd_provider, "te*");
	strcpy(enabled.dtpd_provider, "test-child");
	assert(dt_prog_verify(ctx, base, guest) == 0);
	strcpy(enabled.dtpd_provider, "foreign");
	assert(dt_prog_verify(ctx, base, guest) != 0);
	strcpy(enabled.dtpd_provider, "test");
	strcpy(ecb->dted_probe.dtpd_provider, "test");
	strcpy(enabled.dtpd_name, "other");
	assert(dt_prog_verify(ctx, base, guest) != 0);
	strcpy(enabled.dtpd_name, "probe");
	enabled.dtpd_id = 0;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	enabled.dtpd_id = 1U << 20;
	assert(dt_prog_verify(ctx, base, guest) == 0);
	enabled.dtpd_id = (1U << 20) + 1;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	enabled.dtpd_id = 73;
	enabled.dtpd_provider[0] = '\0';
	assert(dt_prog_verify(ctx, base, guest) != 0);
	strcpy(enabled.dtpd_provider, "test");
	enabled.dtpd_name[0] = '\0';
	assert(dt_prog_verify(ctx, base, guest) != 0);
	strcpy(enabled.dtpd_name, "probe");
	enabled.dtpd_vmid = 7;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	enabled.dtpd_vmid = 0;
	dtrace_probedesc_t enabled_pair[2] = { enabled, enabled };
	guest->dp_eprobes = enabled_pair;
	guest->dp_neprobes = 2;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	enabled_pair[1].dtpd_id = enabled_pair[0].dtpd_id - 1;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	enabled_pair[1].dtpd_id = enabled_pair[0].dtpd_id + 1;
	assert(dt_prog_verify(ctx, base, guest) == 0);
	guest->dp_eprobes = &enabled;
	guest->dp_neprobes = 1;
	memset(enabled.dtpd_provider, 'x', sizeof(enabled.dtpd_provider));
	assert(dt_prog_verify(ctx, base, guest) != 0);
	strcpy(enabled.dtpd_provider, "test");
	guest->dp_neprobes = 64 * 1024 + 1;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest->dp_neprobes = 0;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest->dp_eprobes = NULL;
	guest->dp_exec = base->dp_exec + 1;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest->dp_exec = base->dp_exec;
	guest->dp_rflags = base->dp_rflags ^ 1U;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest->dp_rflags = base->dp_rflags;
	guest->dp_dofversion = base->dp_dofversion + 1;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest->dp_dofversion = base->dp_dofversion;
	assert(dt_prog_verify(ctx, base, empty) != 0);
	base->dp_srcident[0] = 0x7a;
	assert(dt_prog_verify(ctx, base, guest) == 0);
	base_fmt = calloc(1, sizeof(*base_fmt));
	guest_fmt = calloc(1, sizeof(*guest_fmt));
	prefix = calloc(1, sizeof(*prefix));
	assert(base_fmt != NULL && guest_fmt != NULL && prefix != NULL);
	base_fmt->pfv_dtp = guest_fmt->pfv_dtp = dtp;
	base_fmt->pfv_format = strdup("before %d");
	guest_fmt->pfv_format = strdup("guest format");
	assert(base_fmt->pfv_format != NULL && guest_fmt->pfv_format != NULL);
	prefix->pfd_prefix = base_fmt->pfv_format;
	prefix->pfd_preflen = 7;
	base_fmt->pfv_argv = prefix;
	base_fmt->pfv_argc = 1;
	copied = dt_printf_dup(base_fmt);
	assert(copied != NULL && copied->pfv_format != base_fmt->pfv_format &&
	    copied->pfv_argv->pfd_prefix == copied->pfv_format);
	dt_printf_destroy(copied);
	base_first->dtsd_fmtdata = base_fmt;
	guest_first->dtsd_fmtdata = guest_fmt;
	guest->dp_vmid = 7;
	guest_first->dtsd_ecbdesc->dted_probe.dtpd_vmid = 99;
	stmt = dtrace_stmt_create(dtp, ecb);
	assert(stmt != NULL && dtrace_stmt_add(dtp, guest, stmt) == 0);
	assert(dt_prog_verify(ctx, base, guest) != 0);
	assert(guest_first->dtsd_fmtdata == guest_fmt &&
	    guest_first->dtsd_ecbdesc->dted_probe.dtpd_vmid == 99);
	stmt = dtrace_stmt_create(dtp, ecb);
	assert(stmt != NULL && dtrace_stmt_add(dtp, guest_success, stmt) == 0);
	dt_pfargv_t *old_success_fmt = calloc(1, sizeof(*old_success_fmt));
	assert(old_success_fmt != NULL);
	old_success_fmt->pfv_dtp = dtp;
	old_success_fmt->pfv_format = strdup("parsed format");
	assert(old_success_fmt->pfv_format != NULL);
	stmt->dtsd_fmtdata = old_success_fmt;
	guest_success->dp_vmid = 7;
	dt_pfargv_t *verified_fmt;
	assert(dt_prog_verify(ctx, base, guest_success) == 0 &&
	    stmt->dtsd_fmtdata != NULL &&
	    stmt->dtsd_fmtdata != base_fmt &&
	    stmt->dtsd_fmtdata != old_success_fmt);
	verified_fmt = stmt->dtsd_fmtdata;
	assert(verified_fmt->pfv_argv->pfd_prefix ==
	    verified_fmt->pfv_format &&
	    stmt->dtsd_ecbdesc->dted_probe.dtpd_vmid == 7);
	dt_ecbdesc_release(dtp, ecb);
	dt_verictx_teardown(ctx);
	dt_program_destroy(dtp, guest_success);
	dt_program_destroy(dtp, guest);
	dt_program_destroy(dtp, base);
	dt_program_destroy(dtp, empty);
}

static void
verify_action_shape(dtrace_hdl_t *dtp)
{
	dtrace_prog_t *base = dt_program_create(dtp);
	dtrace_prog_t *guest = dt_program_create(dtp);
	dtrace_probedesc_t probe = {};
	dtrace_ecbdesc_t *ecb;
	dtrace_stmtdesc_t *base_stmt, *guest_stmt;
	dtrace_actdesc_t *guest_action;
	dtrace_difo_t empty_difo = {};
	void *ctx = dt_verictx_init(dtp);

	assert(base != NULL && guest != NULL && ctx != NULL);
	strcpy(probe.dtpd_provider, "test");
	strcpy(probe.dtpd_name, "action");
	ecb = dt_ecbdesc_create(dtp, &probe);
	assert(ecb != NULL);
	base_stmt = dtrace_stmt_create(dtp, ecb);
	assert(base_stmt != NULL && dtrace_stmt_add(dtp, base, base_stmt) == 0);
	dt_ecbdesc_release(dtp, ecb);
	ecb = dt_ecbdesc_create(dtp, &probe);
	assert(ecb != NULL);
	guest_stmt = dtrace_stmt_create(dtp, ecb);
	assert(guest_stmt != NULL && dtrace_stmt_add(dtp, guest,
	    guest_stmt) == 0);
	dt_ecbdesc_release(dtp, ecb);
	assert(dtrace_stmt_action(dtp, base_stmt) != NULL);
	guest_action = dtrace_stmt_action(dtp, guest_stmt);
	assert(guest_action != NULL);
	assert(dt_prog_verify(ctx, base, guest) == 0);
	strcpy(guest_stmt->dtsd_ecbdesc->dted_probe.dtpd_target, "wrong");
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_stmt->dtsd_ecbdesc->dted_probe.dtpd_target[0] = '\0';
	guest_action->dtad_arg = 42;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_action->dtad_arg = 0;
	guest_action->dtad_uarg = 0;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_action->dtad_uarg = (uintptr_t)guest_stmt;
	guest_stmt->dtsd_ecbdesc->dted_pred.dtpdd_difo = &empty_difo;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_stmt->dtsd_ecbdesc->dted_pred.dtpdd_difo = NULL;
	guest_action->dtad_difo = &empty_difo;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_action->dtad_difo = NULL;
	assert(dtrace_stmt_action(dtp, guest_stmt) != NULL);
	assert(dt_prog_verify(ctx, base, guest) != 0);
	/* A malformed terminal link used to make the comparison loop skip the
	 * whole action span. A cycle before last must also terminate in error. */
	dtrace_actdesc_t *guest_last = guest_stmt->dtsd_action_last;
	guest_last->dtad_next = guest_action;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	assert(dt_prog_verify(ctx, guest, guest) != 0);
	guest_last->dtad_next = NULL;
	guest_action->dtad_next = guest_action;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_action->dtad_next = guest_last;
	assert(dtrace_stmt_action(dtp, base_stmt) != NULL);
	assert(dt_prog_verify(ctx, base, guest) == 0);
	dtrace_stmtdesc_t *base_follow = dtrace_stmt_create(dtp,
	    base_stmt->dtsd_ecbdesc);
	dtrace_stmtdesc_t *guest_follow = dtrace_stmt_create(dtp,
	    guest_stmt->dtsd_ecbdesc);
	assert(base_follow != NULL && guest_follow != NULL);
	assert(dtrace_stmt_add(dtp, base, base_follow) == 0 &&
	    dtrace_stmt_add(dtp, guest, guest_follow) == 0);
	assert(dtrace_stmt_action(dtp, base_follow) != NULL &&
	    dtrace_stmt_action(dtp, guest_follow) != NULL);
	assert(base_stmt->dtsd_action_last->dtad_next ==
	    base_follow->dtsd_action &&
	    guest_stmt->dtsd_action_last->dtad_next ==
	    guest_follow->dtsd_action);
	assert(dt_prog_verify(ctx, base, guest) == 0);
	dt_verictx_teardown(ctx);
	dt_program_destroy(dtp, guest);
	dt_program_destroy(dtp, base);
}

static void
verify_aggregation_identity(dtrace_hdl_t *dtp)
{
	dtrace_prog_t *base = dt_program_create(dtp);
	dtrace_prog_t *guest = dt_program_create(dtp);
	dtrace_probedesc_t probe = {};
	dtrace_ecbdesc_t *ecb;
	dtrace_stmtdesc_t *base_stmt, *guest_stmt, *extra;
	dt_ident_t base_agg = {}, guest_agg = {};
	void *ctx = dt_verictx_init(dtp);
	int aux = 17;

	assert(base != NULL && guest != NULL && ctx != NULL);
	strcpy(probe.dtpd_provider, "test");
	strcpy(probe.dtpd_name, "aggregation");
	ecb = dt_ecbdesc_create(dtp, &probe);
	assert(ecb != NULL);
	base_stmt = dtrace_stmt_create(dtp, ecb);
	guest_stmt = dtrace_stmt_create(dtp, ecb);
	assert(base_stmt != NULL && guest_stmt != NULL);
	assert(dtrace_stmt_add(dtp, base, base_stmt) == 0);
	assert(dtrace_stmt_add(dtp, guest, guest_stmt) == 0);
	base_agg.di_name = guest_agg.di_name = "@latency";
	base_agg.di_kind = guest_agg.di_kind = DT_IDENT_AGG;
	base_agg.di_id = guest_agg.di_id = 73;
	base_agg.di_data = &aux;
	base_stmt->dtsd_aggdata = &base_agg;
	guest_stmt->dtsd_aggdata = &guest_agg;
	assert(dt_prog_verify(ctx, base, guest) == 0);
	assert(guest_stmt->dtsd_aggdata == &base_agg);
	guest_stmt->dtsd_aggdata = &guest_agg;
	guest_agg.di_id++;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	assert(guest_stmt->dtsd_aggdata == &guest_agg);
	guest_agg.di_id--;
	guest_agg.di_name = "@other";
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_agg.di_name = "@latency";
	guest_agg.di_kind = DT_IDENT_SCALAR;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_agg.di_kind = DT_IDENT_AGG;
	guest_agg.di_flags = 1;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_agg.di_flags = 0;
	guest_agg.di_vers = 1;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_agg.di_vers = 0;
	guest_agg.di_attr.dtat_data++;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_agg.di_attr.dtat_data--;
	guest_stmt->dtsd_descattr.dtat_name++;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_stmt->dtsd_descattr.dtat_name--;
	guest_stmt->dtsd_stmtattr.dtat_class++;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_stmt->dtsd_stmtattr.dtat_class--;
	guest_stmt->dtsd_aggdata = NULL;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	guest_stmt->dtsd_aggdata = &guest_agg;
	base_stmt->dtsd_aggdata = NULL;
	assert(dt_prog_verify(ctx, base, guest) != 0);
	base_stmt->dtsd_aggdata = &base_agg;
	extra = dtrace_stmt_create(dtp, ecb);
	assert(extra != NULL && dtrace_stmt_add(dtp, guest, extra) == 0);
	assert(dt_prog_verify(ctx, base, guest) != 0);
	assert(guest_stmt->dtsd_aggdata == &guest_agg);
	dt_ecbdesc_release(dtp, ecb);
	dt_verictx_teardown(ctx);
	dt_program_destroy(dtp, guest);
	dt_program_destroy(dtp, base);
}

static dtrace_difo_t *
capture_difo(dtrace_hdl_t *dtp, const dif_instr_t *instructions, size_t count)
{
	dtrace_difo_t *difo = dt_zalloc(dtp, sizeof(*difo));
	assert(difo != NULL);
	difo->dtdo_buf = dt_alloc(dtp, count * sizeof(*instructions));
	assert(difo->dtdo_buf != NULL);
	memcpy(difo->dtdo_buf, instructions, count * sizeof(*instructions));
	difo->dtdo_len = count;
	return (difo);
}

static void
verify_high_arg_capture(dtrace_hdl_t *dtp, const dif_instr_t *predicate,
    size_t predicate_len, const dif_instr_t *action_code, size_t action_len,
    uint_t action_kind, unsigned expected_mask)
{
	dtrace_prog_t *source = dt_program_create(dtp);
	dtrace_prog_t *guest;
	dtrace_probedesc_t probe = {};
	dtrace_ecbdesc_t *ecb;
	dtrace_stmtdesc_t *statement;
	dtrace_actdesc_t *action;
	dt_stmt_t *node;
	dtrace_difo_t *forwarding;
	unsigned seen = 0;

	assert(source != NULL);
	strcpy(source->dp_vmname, "guest");
	strcpy(probe.dtpd_target, "guest");
	strcpy(probe.dtpd_provider, "test");
	strcpy(probe.dtpd_name, "high-args");
	ecb = dt_ecbdesc_create(dtp, &probe);
	assert(ecb != NULL);
	if (predicate_len != 0)
		ecb->dted_pred.dtpdd_difo = capture_difo(dtp, predicate,
		    predicate_len);
	statement = dtrace_stmt_create(dtp, ecb);
	assert(statement != NULL);
	action = dtrace_stmt_action(dtp, statement);
	assert(action != NULL);
	action->dtad_kind = action_kind;
	if (action_len != 0)
		action->dtad_difo = capture_difo(dtp, action_code, action_len);
	assert(dtrace_stmt_add(dtp, source, statement) == 0);
	dt_ecbdesc_release(dtp, ecb);
	guest = dtrace_vprog_from(dtp, source, PGP_KIND_HYPERCALLS);
	assert(guest != NULL);
	node = dt_list_next(&guest->dp_stmts);
	assert(node != NULL && dt_list_next(node) == NULL);
	forwarding = node->ds_desc->dtsd_action_last->dtad_difo;
	assert(forwarding != NULL && forwarding->dtdo_len >= 2);
	for (size_t i = 0; i < forwarding->dtdo_len - 2; i++) {
		dif_instr_t instruction = forwarding->dtdo_buf[i];
		uint16_t var = DIF_INSTR_VAR(instruction);
		assert(DIF_INSTR_OP(instruction) == DIF_OP_LDGS &&
		    var >= DIF_VAR_ARG5 && var <= DIF_VAR_ARG9);
		unsigned bit = 1U << (var - DIF_VAR_ARG5);
		assert((seen & bit) == 0);
		seen |= bit;
	}
	assert(seen == expected_mask &&
	    DIF_INSTR_OP(forwarding->dtdo_buf[forwarding->dtdo_len - 2]) ==
	    DIF_OP_HYPERCALL &&
	    DIF_INSTR_R1(forwarding->dtdo_buf[forwarding->dtdo_len - 2]) == 0 &&
	    DIF_INSTR_OP(forwarding->dtdo_buf[forwarding->dtdo_len - 1]) ==
	    DIF_OP_RET);
	dt_program_destroy(dtp, guest);
	dt_program_destroy(dtp, source);
}

static void
verify_guest_time_capture(dtrace_hdl_t *dtp, bool in_predicate,
    bool vtime, bool walltime)
{
	dtrace_prog_t *source = dt_program_create(dtp), *guest;
	dtrace_probedesc_t probe = {};
	dtrace_ecbdesc_t *ecb;
	dtrace_stmtdesc_t *statement;
	dtrace_actdesc_t *action;
	dtrace_difo_t *original, *forwarding;
	dt_stmt_t *node;
	dif_instr_t code[3];
	uint32_t ids[2];
	const char *names[2];
	size_t count = 0;

	assert(vtime || walltime);
	if (vtime) {
		ids[count] = DIF_VAR_VTIMESTAMP;
		names[count++] = "vtimestamp";
	}
	if (walltime) {
		ids[count] = DIF_VAR_WALLTIMESTAMP;
		names[count++] = "walltimestamp";
	}
	for (size_t i = 0; i < count; i++)
		code[i] = DIF_INSTR_LDV(DIF_OP_LDGS, ids[i], 1);
	code[count] = DIF_INSTR_RET(1);

	assert(source != NULL);
	strcpy(source->dp_vmname, "guest");
	strcpy(probe.dtpd_target, "guest");
	strcpy(probe.dtpd_provider, "test");
	strcpy(probe.dtpd_name, "guest-time");
	ecb = dt_ecbdesc_create(dtp, &probe);
	assert(ecb != NULL);
	statement = dtrace_stmt_create(dtp, ecb);
	assert(statement != NULL);
	action = dtrace_stmt_action(dtp, statement);
	assert(action != NULL);
	action->dtad_kind = DTRACEACT_DIFEXPR;
	original = capture_difo(dtp, code, count + 1);
	original->dtdo_vartab = calloc(count, sizeof(*original->dtdo_vartab));
	assert(original->dtdo_vartab != NULL);
	original->dtdo_varlen = count;
	for (size_t i = 0; i < count; i++) {
		original->dtdo_vartab[i].dtdv_id = ids[i];
		original->dtdo_vartab[i].dtdv_kind = DIFV_KIND_SCALAR;
		original->dtdo_vartab[i].dtdv_scope = DIFV_SCOPE_GLOBAL;
		original->dtdo_vartab[i].dtdv_flags = DIFV_F_REF;
		original->dtdo_vartab[i].dtdv_type.dtdt_kind = DIF_TYPE_CTF;
		original->dtdo_vartab[i].dtdv_type.dtdt_size = sizeof(uint64_t);
	}
	if (in_predicate)
		ecb->dted_pred.dtpdd_difo = original;
	else
		action->dtad_difo = original;
	assert(dtrace_stmt_add(dtp, source, statement) == 0);
	dt_ecbdesc_release(dtp, ecb);
	guest = dtrace_vprog_from(dtp, source, PGP_KIND_HYPERCALLS);
	assert(guest != NULL);
	node = dt_list_next(&guest->dp_stmts);
	assert(node != NULL && dt_list_next(node) == NULL);
	forwarding = node->ds_desc->dtsd_action_last->dtad_difo;
	assert(forwarding != NULL && forwarding->dtdo_len == count + 2);
	assert(forwarding->dtdo_varlen == count &&
	    forwarding->dtdo_strtab != NULL);
	size_t offset = 0;
	for (size_t i = 0; i < count; i++) {
		assert(DIF_INSTR_OP(forwarding->dtdo_buf[i]) == DIF_OP_LDGS &&
		    DIF_INSTR_VAR(forwarding->dtdo_buf[i]) == ids[i] &&
		    forwarding->dtdo_vartab[i].dtdv_id == ids[i] &&
		    forwarding->dtdo_vartab[i].dtdv_type.dtdt_size ==
		    sizeof(uint64_t) &&
		    forwarding->dtdo_vartab[i].dtdv_name == offset &&
		    strcmp(forwarding->dtdo_strtab + offset, names[i]) == 0);
		offset += strlen(names[i]) + 1;
	}
	assert(forwarding->dtdo_strlen == offset &&
	    DIF_INSTR_OP(forwarding->dtdo_buf[count]) == DIF_OP_HYPERCALL &&
	    DIF_INSTR_OP(forwarding->dtdo_buf[count + 1]) == DIF_OP_RET);
	dt_program_destroy(dtp, guest);
	dt_program_destroy(dtp, source);
}

static void
verify_guest_stack_capture(dtrace_hdl_t *dtp, uint64_t requested,
    uint_t expected, bool accepted)
{
	dtrace_prog_t *source = dt_program_create(dtp), *guest;
	dtrace_probedesc_t probe = {};
	dtrace_ecbdesc_t *ecb;
	dtrace_stmtdesc_t *statement;
	dtrace_actdesc_t *action;
	dtrace_difo_t *forwarding;
	dt_stmt_t *node;

	assert(source != NULL);
	strcpy(source->dp_vmname, "guest");
	strcpy(probe.dtpd_target, "guest");
	strcpy(probe.dtpd_provider, "test");
	strcpy(probe.dtpd_name, "stack");
	ecb = dt_ecbdesc_create(dtp, &probe);
	assert(ecb != NULL);
	statement = dtrace_stmt_create(dtp, ecb);
	assert(statement != NULL);
	action = dtrace_stmt_action(dtp, statement);
	assert(action != NULL);
	action->dtad_kind = DTRACEACT_STACK;
	action->dtad_arg = requested;
	assert(dtrace_stmt_add(dtp, source, statement) == 0);
	dt_ecbdesc_release(dtp, ecb);
	guest = dtrace_vprog_from(dtp, source, PGP_KIND_HYPERCALLS);
	if (!accepted) {
		assert(guest == NULL && action->dtad_arg == requested);
	} else {
		assert(guest != NULL);
		node = dt_list_next(&guest->dp_stmts);
		assert(node != NULL && dt_list_next(node) == NULL);
		forwarding = node->ds_desc->dtsd_action_last->dtad_difo;
		assert(forwarding != NULL && forwarding->dtdo_len >= 2);
		assert(DIF_INSTR_OP(forwarding->dtdo_buf[
		    forwarding->dtdo_len - 2]) == DIF_OP_HYPERCALL &&
		    DIF_INSTR_R1(forwarding->dtdo_buf[
		    forwarding->dtdo_len - 2]) == expected &&
		    action->dtad_arg == expected);
		dt_program_destroy(dtp, guest);
	}
	dt_program_destroy(dtp, source);
}

int
main(void)
{
	dtrace_hdl_t *dtp = calloc(1, sizeof(*dtp));
	dtrace_prog_t *source, *guest;
	dtrace_ecbdesc_t *ecb;
	dtrace_stmtdesc_t *statement;
	dtrace_actdesc_t *action;
	dtrace_probedesc_t probe = {};
	dt_stmt_t *node;
	const char *names[] = { "a", "b", "a", "ERROR" };
	size_t count;
	bool saw_guest_error = false;

	assert(dtp != NULL);
	assert(dt_verictx_mark(NULL) == 0);
	dt_verictx_rewind(NULL, 0);
	verify_relocations(dtp);
	verify_difo_metadata(dtp);
	verify_failed_difo_program(dtp);
	verify_program_shape(dtp);
	verify_action_shape(dtp);
	verify_aggregation_identity(dtp);
	const dif_instr_t pred_high[] = {
	    DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG7, 1) };
	const dif_instr_t action_high[] = {
	    DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ARG9, 1) };
	const dif_instr_t indexed_args[] = {
	    DIF_INSTR_SETX(0, 2),
	    DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3) };
	const dif_instr_t translated_args[] = {
	    DIF_INSTR_FMT(DIF_OP_XLARG, 0, 0, 1) };
	const dif_instr_t addressed_args[] = {
	    DIF_INSTR_LDV(DIF_OP_LDGAA, DIF_VAR_ARGS, 1) };
	const dif_instr_t register_array[] = {
	    DIF_INSTR_LDA(DIF_OP_LDGA, DIF_VAR_REGS, 2, 3) };
	verify_high_arg_capture(dtp, pred_high, 1, NULL, 0,
	    DTRACEACT_IMMSTACK, 1U << 2);
	verify_high_arg_capture(dtp, NULL, 0, action_high, 1,
	    DTRACEACT_TRACEMEM, 1U << 4);
	verify_high_arg_capture(dtp, NULL, 0, indexed_args, 2,
	    DTRACEACT_DIFEXPR, 0x1f);
	verify_high_arg_capture(dtp, NULL, 0, translated_args, 1,
	    DTRACEACT_DIFEXPR, 0x1f);
	verify_high_arg_capture(dtp, NULL, 0, addressed_args, 1,
	    DTRACEACT_DIFEXPR, 0x1f);
	verify_high_arg_capture(dtp, NULL, 0, register_array, 1,
	    DTRACEACT_DIFEXPR, 0);
	verify_guest_time_capture(dtp, true, true, false);
	verify_guest_time_capture(dtp, false, true, false);
	verify_guest_time_capture(dtp, true, false, true);
	verify_guest_time_capture(dtp, false, false, true);
	verify_guest_time_capture(dtp, false, true, true);
	dtp->dt_options[DTRACEOPT_STACKFRAMES] = DTRACEOPT_UNSET;
	verify_guest_stack_capture(dtp, 0, 20, true);
	verify_guest_stack_capture(dtp, 64, 64, true);
	verify_guest_stack_capture(dtp, 65, 0, false);
	source = dt_program_create(dtp);
	assert(source != NULL);
	strcpy(source->dp_vmname, "guest");
	for (size_t i = 0; i < 4; i++) {
		memset(&probe, 0, sizeof(probe));
		strcpy(probe.dtpd_target, i == 3 ? "original" : "guest");
		strcpy(probe.dtpd_provider, i == 3 ? "dtrace" : "test");
		strcpy(probe.dtpd_name, names[i]);
		ecb = dt_ecbdesc_create(dtp, &probe);
		assert(ecb != NULL);
		statement = dtrace_stmt_create(dtp, ecb);
		assert(statement != NULL);
		action = dtrace_stmt_action(dtp, statement);
		assert(action != NULL);
		action->dtad_kind = DTRACEACT_IMMSTACK;
		action->dtad_arg = 3;
		assert(dtrace_stmt_add(dtp, source, statement) == 0);
		dt_ecbdesc_release(dtp, ecb);
	}
	guest = dtrace_vprog_from(dtp, source, PGP_KIND_HYPERCALLS);
	assert(guest != NULL);
	count = 0;
	for (node = dt_list_next(&guest->dp_stmts); node;
	    node = dt_list_next(node)) {
		count++;
		ecb = node->ds_desc->dtsd_ecbdesc;
		if (strcmp(ecb->dted_probe.dtpd_name, "ERROR") == 0) {
			assert(strcmp(ecb->dted_probe.dtpd_target, "guest") == 0);
			saw_guest_error = true;
		}
	}
	/* One forwarding statement per probe (a, b, ERROR): a firing makes
	 * one hypercall, and the host runs each clause once for it. */
	assert(count == 3 && saw_guest_error);
	for (node = dt_list_next(&source->dp_stmts); node;
	    node = dt_list_next(node)) {
		assert(node->ds_desc->dtsd_action->dtad_kind ==
		    DTRACEACT_PRINTIMMSTACK);
		if (strcmp(node->ds_desc->dtsd_ecbdesc->dted_probe.dtpd_name,
		    "ERROR") == 0)
			assert(strcmp(node->ds_desc->dtsd_ecbdesc->dted_probe.
			    dtpd_target, "original") == 0);
	}
	dt_program_destroy(dtp, guest);
	dt_program_destroy(dtp, source);
	/* Malformed probe names fail without mutating the source program. */
	source = dt_program_create(dtp);
	assert(source != NULL);
	memset(&probe, 0, sizeof(probe));
	strcpy(probe.dtpd_provider, "test");
	memset(probe.dtpd_name, 'x', sizeof(probe.dtpd_name));
	ecb = dt_ecbdesc_create(dtp, &probe);
	assert(ecb != NULL);
	statement = dtrace_stmt_create(dtp, ecb);
	assert(statement != NULL);
	action = dtrace_stmt_action(dtp, statement);
	assert(action != NULL);
	action->dtad_kind = DTRACEACT_IMMSTACK;
	assert(dtrace_stmt_add(dtp, source, statement) == 0);
	dt_ecbdesc_release(dtp, ecb);
	assert(dtrace_vprog_from(dtp, source, PGP_KIND_HYPERCALLS) == NULL);
	assert(action->dtad_kind == DTRACEACT_IMMSTACK);
	dt_program_destroy(dtp, source);
	free(dtp);
	puts("PASS: vprog transform and verifier relocation/shape checks");
	return (0);
}
