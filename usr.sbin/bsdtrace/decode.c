/*-
 * Copyright (c) 2026 Kory Heard
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * PT decoder — packet-level and instruction-level decoding via libipt.
 *
 * decode_pt_buffer() uses the packet decoder (pt_pkt_*) to dump raw
 * PT packets without needing a binary image.
 *
 * decode_pt_insn() uses the instruction decoder (pt_insn_*) with a
 * pt_image built from EXEC/MMAP records to decode actual control-flow
 * events (calls, returns, branches, syscalls).  ELF parsing and symbol
 * resolution are handled by elf.c and symbols.c.
 */

#include <sys/types.h>

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <intel-pt.h>
#include <pt_cpu.h>

#include "bsdtrace.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static const char *
exec_mode_str(enum pt_exec_mode mode)
{

	switch (mode) {
	case ptem_16bit:	return ("16-bit");
	case ptem_32bit:	return ("32-bit");
	case ptem_64bit:	return ("64-bit");
	default:		return ("unknown");
	}
}

static void
tnt_str(char *buf, size_t bufsz, uint64_t payload, uint8_t bit_size)
{
	int i;

	if ((size_t)bit_size >= bufsz)
		bit_size = (uint8_t)(bufsz - 1);

	for (i = bit_size - 1; i >= 0; i--)
		*buf++ = (payload & (1ULL << i)) ? '!' : '.';
	*buf = '\0';
}

/* ------------------------------------------------------------------ */
/* Packet-level text output                                            */
/* ------------------------------------------------------------------ */

static void
emit_packet_text(const struct pt_packet *pkt)
{
	char tnt[65];

	switch (pkt->type) {
	case ppt_psb:
		printf("  PSB\n");
		break;
	case ppt_psbend:
		printf("  PSBEND\n");
		break;
	case ppt_tip:
		if (pkt->payload.ip.ipc == pt_ipc_suppressed)
			printf("  TIP       suppressed\n");
		else
			printf("  TIP       0x%016lx\n",
			    (unsigned long)pkt->payload.ip.ip);
		break;
	case ppt_tip_pge:
		printf("  TIP.PGE   0x%016lx\n",
		    (unsigned long)pkt->payload.ip.ip);
		break;
	case ppt_tip_pgd:
		if (pkt->payload.ip.ipc == pt_ipc_suppressed)
			printf("  TIP.PGD   suppressed\n");
		else
			printf("  TIP.PGD   0x%016lx\n",
			    (unsigned long)pkt->payload.ip.ip);
		break;
	case ppt_fup:
		if (pkt->payload.ip.ipc == pt_ipc_suppressed)
			printf("  FUP       suppressed\n");
		else
			printf("  FUP       0x%016lx\n",
			    (unsigned long)pkt->payload.ip.ip);
		break;
	case ppt_tnt_8:
	case ppt_tnt_64:
		tnt_str(tnt, sizeof(tnt), pkt->payload.tnt.payload,
		    pkt->payload.tnt.bit_size);
		printf("  TNT       %s\n", tnt);
		break;
	case ppt_mode:
		if (pkt->payload.mode.leaf == pt_mol_exec)
			printf("  MODE.Exec %s\n",
			    exec_mode_str(
			    pt_get_exec_mode(&pkt->payload.mode.bits.exec)));
		else if (pkt->payload.mode.leaf == pt_mol_tsx)
			printf("  MODE.TSX  intx=%d abrt=%d\n",
			    pkt->payload.mode.bits.tsx.intx,
			    pkt->payload.mode.bits.tsx.abrt);
		else
			printf("  MODE      leaf=0x%02x\n",
			    pkt->payload.mode.leaf);
		break;
	case ppt_pip:
		printf("  PIP       cr3=0x%016lx nr=%d\n",
		    (unsigned long)pkt->payload.pip.cr3,
		    pkt->payload.pip.nr);
		break;
	case ppt_tsc:
		printf("  TSC       0x%lx\n",
		    (unsigned long)pkt->payload.tsc.tsc);
		break;
	case ppt_cbr:
		printf("  CBR       ratio=%u\n", pkt->payload.cbr.ratio);
		break;
	case ppt_tma:
		printf("  TMA       ctc=0x%04x fc=0x%04x\n",
		    pkt->payload.tma.ctc, pkt->payload.tma.fc);
		break;
	case ppt_mtc:
		printf("  MTC       ctc=0x%02x\n", pkt->payload.mtc.ctc);
		break;
	case ppt_cyc:
		printf("  CYC       0x%lx\n",
		    (unsigned long)pkt->payload.cyc.value);
		break;
	case ppt_ovf:
		printf("  OVF\n");
		break;
	case ppt_ptw:
		printf("  PTW       ip=%d payload=0x%016lx\n",
		    pkt->payload.ptw.ip,
		    (unsigned long)pkt->payload.ptw.payload);
		break;
	case ppt_stop:
		printf("  STOP\n");
		break;
	case ppt_vmcs:
		printf("  VMCS      0x%016lx\n",
		    (unsigned long)pkt->payload.vmcs.base);
		break;
	case ppt_mnt:
		printf("  MNT       0x%016lx\n",
		    (unsigned long)pkt->payload.mnt.payload);
		break;
	case ppt_exstop:
		printf("  EXSTOP    ip=%d\n", pkt->payload.exstop.ip);
		break;
	case ppt_pad:
		break;
	default:
		printf("  ???       type=%d size=%u\n", pkt->type, pkt->size);
		break;
	}
}

/* ------------------------------------------------------------------ */
/* Packet-level JSON output                                            */
/* ------------------------------------------------------------------ */

static void
emit_packet_json(const struct pt_packet *pkt)
{
	char tnt[65];

	switch (pkt->type) {
	case ppt_psb:
		printf("{\"pkt\":\"psb\"}\n");
		break;
	case ppt_psbend:
		printf("{\"pkt\":\"psbend\"}\n");
		break;
	case ppt_tip:
		if (pkt->payload.ip.ipc == pt_ipc_suppressed)
			printf("{\"pkt\":\"tip\",\"ip\":null}\n");
		else
			printf("{\"pkt\":\"tip\",\"ip\":\"0x%lx\"}\n",
			    (unsigned long)pkt->payload.ip.ip);
		break;
	case ppt_tip_pge:
		printf("{\"pkt\":\"tip_pge\",\"ip\":\"0x%lx\"}\n",
		    (unsigned long)pkt->payload.ip.ip);
		break;
	case ppt_tip_pgd:
		if (pkt->payload.ip.ipc == pt_ipc_suppressed)
			printf("{\"pkt\":\"tip_pgd\",\"ip\":null}\n");
		else
			printf("{\"pkt\":\"tip_pgd\",\"ip\":\"0x%lx\"}\n",
			    (unsigned long)pkt->payload.ip.ip);
		break;
	case ppt_fup:
		if (pkt->payload.ip.ipc == pt_ipc_suppressed)
			printf("{\"pkt\":\"fup\",\"ip\":null}\n");
		else
			printf("{\"pkt\":\"fup\",\"ip\":\"0x%lx\"}\n",
			    (unsigned long)pkt->payload.ip.ip);
		break;
	case ppt_tnt_8:
	case ppt_tnt_64:
		tnt_str(tnt, sizeof(tnt), pkt->payload.tnt.payload,
		    pkt->payload.tnt.bit_size);
		printf("{\"pkt\":\"tnt\",\"bits\":\"%s\"}\n", tnt);
		break;
	case ppt_mode:
		if (pkt->payload.mode.leaf == pt_mol_exec)
			printf("{\"pkt\":\"mode_exec\",\"mode\":\"%s\"}\n",
			    exec_mode_str(
			    pt_get_exec_mode(&pkt->payload.mode.bits.exec)));
		else if (pkt->payload.mode.leaf == pt_mol_tsx)
			printf("{\"pkt\":\"mode_tsx\",\"intx\":%d,\"abrt\":%d}\n",
			    pkt->payload.mode.bits.tsx.intx,
			    pkt->payload.mode.bits.tsx.abrt);
		break;
	case ppt_pip:
		printf("{\"pkt\":\"pip\",\"cr3\":\"0x%lx\",\"nr\":%d}\n",
		    (unsigned long)pkt->payload.pip.cr3,
		    pkt->payload.pip.nr);
		break;
	case ppt_tsc:
		printf("{\"pkt\":\"tsc\",\"tsc\":%lu}\n",
		    (unsigned long)pkt->payload.tsc.tsc);
		break;
	case ppt_cbr:
		printf("{\"pkt\":\"cbr\",\"ratio\":%u}\n",
		    pkt->payload.cbr.ratio);
		break;
	case ppt_ovf:
		printf("{\"pkt\":\"ovf\"}\n");
		break;
	case ppt_ptw:
		printf("{\"pkt\":\"ptw\",\"ip\":%d,\"payload\":\"0x%lx\"}\n",
		    pkt->payload.ptw.ip,
		    (unsigned long)pkt->payload.ptw.payload);
		break;
	case ppt_stop:
		printf("{\"pkt\":\"stop\"}\n");
		break;
	case ppt_pad:
		break;
	default:
		break;
	}
}

/* ------------------------------------------------------------------ */
/* Packet-level decoder                                                */
/* ------------------------------------------------------------------ */

int
decode_pt_buffer(const void *buf, size_t len, enum bsdtrace_fmt fmt)
{
	struct pt_config config;
	struct pt_packet_decoder *decoder;
	struct pt_packet pkt;
	int total, errors, syncs;
	int status;

	if (buf == NULL || len == 0) {
		warnx("no PT data to decode");
		return (-1);
	}

	pt_config_init(&config);
	config.begin = __DECONST(uint8_t *, buf);
	config.end = __DECONST(uint8_t *, buf) + len;

	if (pt_cpu_read(&config.cpu) == 0)
		pt_cpu_errata(&config.errata, &config.cpu);

	decoder = pt_pkt_alloc_decoder(&config);
	if (decoder == NULL) {
		warnx("pt_pkt_alloc_decoder failed");
		return (-1);
	}

	if (fmt == FMT_TEXT) {
		fprintf(stderr,
		    "\nPT Packets (%zu bytes)\n"
		    "────────────────────────────────────────\n", len);
	}

	total = 0;
	errors = 0;
	syncs = 0;

	status = pt_pkt_sync_forward(decoder);
	while (status >= 0) {
		syncs++;

		for (;;) {
			status = pt_pkt_next(decoder, &pkt, sizeof(pkt));
			if (status < 0)
				break;

			total++;

			if (fmt == FMT_JSON)
				emit_packet_json(&pkt);
			else
				emit_packet_text(&pkt);
		}

		if (status == -pte_eos)
			break;

		errors++;
		status = pt_pkt_sync_forward(decoder);
	}

	pt_pkt_free_decoder(decoder);

	if (fmt == FMT_TEXT)
		fprintf(stderr,
		    "%d packets decoded, %d sync points, %d errors\n",
		    total, syncs, errors);

	return (total > 0 ? 0 : -1);
}

/* ================================================================== */
/* Instruction-level decoder                                           */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/* Image builder — orchestrates elf.c and symbols.c                    */
/* ------------------------------------------------------------------ */

static struct pt_image *
build_pt_image(const struct pt_image_info *sections, int nsections,
    struct sym_table *st, bool verbose)
{
	struct pt_image *image;
	char interp[MAXPATHLEN];
	uint64_t base_vaddr;
	int64_t slide;
	int total, i;
	Elf *elf;
	int fd;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		warnx("elf_version: %s", elf_errmsg(-1));
		return (NULL);
	}

	image = pt_image_alloc("bsdtrace");
	if (image == NULL)
		return (NULL);

	total = 0;
	for (i = 0; i < nsections; i++) {
		uint64_t load_addr;
		bool have_load_addr;

		if (!section_should_use(sections, nsections, i))
			continue;

		load_addr = sections[i].load_addr;
		have_load_addr = false;
		fd = open(sections[i].path, O_RDONLY);
		if (fd >= 0) {
			elf = elf_begin(fd, ELF_C_READ, NULL);
			if (elf != NULL) {
				if (elf_effective_load_addr(elf,
				    sections[i].type,
				    sections[i].load_addr,
				    sections[i].pgoff,
				    sections[i].maplen, &load_addr) == 0)
					have_load_addr = true;
				elf_end(elf);
			}
			close(fd);
		}
		if (!have_load_addr)
			continue;

		{
			int segs = add_elf_to_image(image,
			    sections[i].path, load_addr);
			total += segs;
			if (verbose) {
				fprintf(stderr,
				    "  [%d] %s type=%d rec_addr=0x%lx "
				    "load_addr=0x%lx segs=%d\n",
				    i, sections[i].path, sections[i].type,
				    (unsigned long)sections[i].load_addr,
				    (unsigned long)load_addr, segs);
			}
		}

		/* Load symbols with the same slide. */
		fd = open(sections[i].path, O_RDONLY);
		if (fd >= 0) {
			elf = elf_begin(fd, ELF_C_READ, NULL);
			if (elf != NULL) {
				if (elf_base_vaddr(elf, &base_vaddr) == 0) {
					slide = (int64_t)load_addr -
					    (int64_t)base_vaddr;
					if (verbose) {
						fprintf(stderr,
						    "    base_vaddr=0x%lx "
						    "slide=0x%lx\n",
						    (unsigned long)base_vaddr,
						    (unsigned long)slide);
					}
					sym_table_add_elf(st,
					    sections[i].path, slide);
				}
				elf_end(elf);
			}
			close(fd);
		}

		/*
		 * Handle interpreter for EXEC records.
		 *
		 * Skip if the interpreter already has its own MMAP
		 * section — that section will be processed on its
		 * own iteration and we'd just duplicate the work.
		 */
		if (sections[i].type == HWT_RECORD_EXECUTABLE &&
		    is_user_addr(sections[i].base_addr) &&
		    sections[i].base_addr != load_addr) {
			if (elf_get_interp(sections[i].path,
			    interp, sizeof(interp)) == 0) {
				int k;
				bool have_mmap = false;

				for (k = 0; k < nsections; k++) {
					if (sections[k].type ==
					    HWT_RECORD_MMAP &&
					    strcmp(sections[k].path,
					    interp) == 0) {
						have_mmap = true;
						break;
					}
				}

				if (!have_mmap) {
					total += add_elf_to_image(image,
					    interp,
					    sections[i].base_addr);

					fd = open(interp, O_RDONLY);
					if (fd >= 0) {
						elf = elf_begin(fd,
						    ELF_C_READ, NULL);
						if (elf != NULL) {
							if (elf_base_vaddr(
							    elf,
							    &base_vaddr)
							    == 0) {
								slide =
								    (int64_t)sections[i].base_addr -
								    (int64_t)base_vaddr;
								sym_table_add_elf(
								    st, interp,
								    slide);
							}
							elf_end(elf);
						}
						close(fd);
					}
				}
			}
		}
	}

	sym_table_sort(st);

	if (verbose) {
		fprintf(stderr, "image: %d sections, %d segments, %d symbols\n",
		    nsections, total, st->count);
	}

	if (total == 0) {
		warnx("no executable segments found in %d binaries",
		    nsections);
		pt_image_free(image);
		return (NULL);
	}

	return (image);
}

/* ------------------------------------------------------------------ */
/* Instruction classification                                          */
/* ------------------------------------------------------------------ */

static const char *
insn_class_str(enum pt_insn_class iclass)
{

	switch (iclass) {
	case ptic_call:		return ("CALL");
	case ptic_return:	return ("RETURN");
	case ptic_jump:		return ("JUMP");
	case ptic_cond_jump:	return ("CJMP");
	case ptic_far_call:	return ("FARCALL");
	case ptic_far_return:	return ("FARRET");
	case ptic_far_jump:	return ("FARJMP");
	case ptic_ptwrite:	return ("PTWRITE");
	default:		return (NULL);
	}
}

static const char *
path_basename(const char *path)
{
	const char *slash;

	slash = strrchr(path, '/');
	if (slash != NULL && slash[1] != '\0')
		return (slash + 1);
	return (path);
}

static int
collect_exec_binaries(const struct pt_image_info *sections, int nsections,
    char exec_bins[][64], int maxbins)
{
	const char *bn;
	int i, j, nbins;

	nbins = 0;
	for (i = 0; i < nsections && nbins < maxbins; i++) {
		if (sections[i].type != HWT_RECORD_EXECUTABLE)
			continue;
		if (sections[i].path[0] == '\0')
			continue;

		bn = path_basename(sections[i].path);
		for (j = 0; j < nbins; j++) {
			if (strcmp(exec_bins[j], bn) == 0)
				break;
		}
		if (j != nbins)
			continue;

		strlcpy(exec_bins[nbins], bn, sizeof(exec_bins[nbins]));
		nbins++;
	}

	return (nbins);
}

static bool
is_exec_binary(const char *binary, char exec_bins[][64], int nbins)
{
	int i;

	if (binary == NULL || binary[0] == '\0')
		return (false);

	for (i = 0; i < nbins; i++) {
		if (strcmp(exec_bins[i], binary) == 0)
			return (true);
	}

	return (false);
}

/*
 * Apply the capture-machine environment (from the .meta sidecar) to
 * a libipt configuration.  Falls back to the local CPU only when no
 * capture environment is available — decoding a trace with the
 * decode host's CPUID would misapply errata and, worse, silently
 * disable MTC-based timing on any machine whose CPUID 0x15 differs.
 */
static void
config_apply_env(struct pt_config *config, const struct pt_decode_opts *opts)
{
	int i;

	if (opts != NULL && opts->env.valid) {
		config->cpu.vendor = pcv_intel;
		config->cpu.family = opts->env.family;
		config->cpu.model = opts->env.model;
		config->cpu.stepping = opts->env.stepping;
		if (pt_cpu_errata(&config->errata, &config->cpu) < 0)
			memset(&config->errata, 0,
			    sizeof(config->errata));
		config->cpuid_0x15_eax = opts->env.cpuid_15_eax;
		config->cpuid_0x15_ebx = opts->env.cpuid_15_ebx;
		config->nom_freq = opts->env.nom_freq;
		for (i = 0; i < opts->env.nranges && i < 2; i++) {
			if (i == 0) {
				config->addr_filter.config.ctl.addr0_cfg =
				    (uint32_t)opts->env.range_cfg[0];
				config->addr_filter.addr0_a =
				    opts->env.range_a[0];
				config->addr_filter.addr0_b =
				    opts->env.range_b[0];
			} else {
				config->addr_filter.config.ctl.addr1_cfg =
				    (uint32_t)opts->env.range_cfg[1];
				config->addr_filter.addr1_a =
				    opts->env.range_a[1];
				config->addr_filter.addr1_b =
				    opts->env.range_b[1];
			}
		}
	} else if (pt_cpu_read(&config->cpu) == 0)
		pt_cpu_errata(&config->errata, &config->cpu);
}

/*
 * pt_insn_sync_forward with a forward-progress guard: a sync error
 * other than end-of-stream (e.g. a corrupt PSB+ header at a wrap
 * seam) is retried from the next sync point, but only while the
 * decoder's offset advances — otherwise a partially-consumed PSB
 * could spin forever.
 */
static int
resync_forward(struct pt_insn_decoder *decoder, uint64_t *last_sync)
{
	uint64_t offset;
	int status;

	for (;;) {
		status = pt_insn_sync_forward(decoder);
		if (status >= 0 || status == -pte_eos)
			return (status);
		if (pt_insn_get_offset(decoder, &offset) < 0 ||
		    offset <= *last_sync)
			return (status);
		*last_sync = offset;
	}
}

int
decode_pt_probe(const void *buf, size_t len,
    const struct pt_image_info *sections, int nsections,
    const struct pt_decode_opts *opts,
    struct decode_probe_result *result)
{
	struct pt_config config;
	struct pt_insn_decoder *decoder;
	struct pt_image *image;
	struct sym_table st;
	struct bin_range ranges[MAX_BIN_RANGES];
	struct pt_insn insn;
	struct decode_probe_result probe;
	char exec_bins[16][64];
	const struct sym_entry *sym;
	const char *bn;
	uint64_t boff, last_sync;
	int nbins, nranges, status;

	if (result == NULL)
		return (-1);

	memset(&probe, 0, sizeof(probe));
	*result = probe;

	if (buf == NULL || len == 0 || nsections <= 0)
		return (-1);

	sym_table_init(&st);

	image = build_pt_image(sections, nsections, &st, false);
	if (image == NULL) {
		sym_table_free(&st);
		return (-1);
	}

	nbins = collect_exec_binaries(sections, nsections, exec_bins,
	    nitems(exec_bins));
	nranges = build_bin_ranges(sections, nsections, ranges,
	    MAX_BIN_RANGES);

	pt_config_init(&config);
	config.begin = __DECONST(uint8_t *, buf);
	config.end = __DECONST(uint8_t *, buf) + len;
	config_apply_env(&config, opts);

	decoder = pt_insn_alloc_decoder(&config);
	if (decoder == NULL) {
		pt_image_free(image);
		sym_table_free(&st);
		return (-1);
	}

	status = pt_insn_set_image(decoder, image);
	if (status < 0) {
		pt_insn_free_decoder(decoder);
		pt_image_free(image);
		sym_table_free(&st);
		return (-1);
	}

	last_sync = 0;
	status = resync_forward(decoder, &last_sync);
	while (status >= 0) {
		while (status & pts_event_pending) {
			struct pt_event ev;

			status = pt_insn_event(decoder, &ev, sizeof(ev));
			if (status < 0)
				break;
		}
		if (status < 0) {
			if (status == -pte_eos)
				break;
			status = resync_forward(decoder, &last_sync);
			continue;
		}
		/* End of trace: don't count statically-inferred flow. */
		if (status & pts_eos)
			break;

		status = pt_insn_next(decoder, &insn, sizeof(insn));
		if (status < 0) {
			if (status == -pte_eos)
				break;
			status = resync_forward(decoder, &last_sync);
			continue;
		}

		probe.total++;
		sym = sym_table_lookup(&st, insn.ip);
		bn = NULL;
		boff = 0;
		if (sym == NULL)
			bn = find_binary_for_ip(ranges, nranges, insn.ip,
			    &boff);

		if ((sym != NULL && is_exec_binary(sym->binary, exec_bins, nbins)) ||
		    (bn != NULL && is_exec_binary(bn, exec_bins, nbins)))
			probe.exec_hits++;
	}

	pt_insn_free_decoder(decoder);
	pt_image_free(image);
	sym_table_free(&st);
	*result = probe;
	return (probe.total > 0 ? 0 : -1);
}

/* ------------------------------------------------------------------ */
/* Profile counters                                                    */
/* ------------------------------------------------------------------ */

struct profile_entry {
	const char	*name;		/* sym name (borrowed from sym_table) */
	const char	*binary;	/* binary name (borrowed) */
	int		calls;
	int		returns;
	int		branches;
	uint64_t	cumulative_tsc;	/* sum of per-call TSC deltas */
	char		*source_file;	/* DWARF file path (strdup'd, or NULL) */
	int		source_line;	/* DWARF line number (0 = unknown) */
};

#define	PROF_ACT_MAX	512		/* activation stack depth cap */

struct profile {
	struct profile_entry	*entries;
	int			count;
	int			capacity;
	enum pt_insn_class	prev_class;
	/*
	 * Per-activation entry timestamps so recursive calls do not
	 * clobber outer activations' timing.  Entries are recorded by
	 * index (entries[] may be realloc'd, so pointers would dangle).
	 */
	int			act_ent[PROF_ACT_MAX];
	uint64_t		act_tsc[PROF_ACT_MAX];
	int			act_depth;
	int			act_overflow;	/* pushes dropped at cap */
	int			async_depth;	/* pending interrupt markers */
};

static void
profile_init(struct profile *p)
{

	memset(p, 0, sizeof(*p));
}

/*
 * Record a profile event.
 *
 * "calls" counts function entries: an instruction at offset 0 within
 * a symbol is an entry (the first instruction after a CALL lands at
 * the target function's start address).
 *
 * "returns" counts RETURN events within the function.
 * "branches" counts JUMP/CJMP events within the function.
 */
static void
profile_record(struct profile *p, const struct sym_entry *sym,
    uint64_t ip, enum pt_insn_class iclass, uint64_t tsc,
    const struct pt_image_info *sections, int nsections)
{
	struct profile_entry *e;
	int i;

	if (sym == NULL) {
		/*
		 * Track control flow through unsymbolized code (PLT
		 * stubs, JIT) so a call that reaches a function entry
		 * via a stub still counts, but a stale call class from
		 * long ago does not.  A call latches; a return clears;
		 * plain jumps preserve the latch (PLT stubs are jumps).
		 */
		if (iclass == ptic_call || iclass == ptic_far_call)
			p->prev_class = iclass;
		else if (iclass == ptic_far_return && p->async_depth > 0)
			p->async_depth--;	/* interrupt IRET: keep latch */
		else if (iclass == ptic_return || iclass == ptic_far_return)
			p->prev_class = ptic_error;
		return;
	}

	/* Find or create entry. */
	e = NULL;
	for (i = 0; i < p->count; i++) {
		if (p->entries[i].name == sym->name &&
		    p->entries[i].binary == sym->binary) {
			e = &p->entries[i];
			break;
		}
	}

	if (e == NULL) {
		if (p->count >= p->capacity) {
			int newcap = p->capacity == 0 ? 128 : p->capacity * 2;
			struct profile_entry *newent;

			newent = realloc(p->entries,
			    newcap * sizeof(*newent));
			if (newent == NULL)
				return;
			p->entries = newent;
			p->capacity = newcap;
		}

		e = &p->entries[p->count];
		memset(e, 0, sizeof(*e));
		e->name = sym->name;
		e->binary = sym->binary;
		p->count++;

		/* DWARF lookup — once per function.
		 * Find the section that contains this symbol's address
		 * to get the full binary path and compute the slide.
		 * The slide is load_addr - elf_base_vaddr, same as
		 * build_pt_image uses for libipt. */
		if (sections != NULL) {
			struct dwarf_cache *dc;
			char srcfile[MAXPATHLEN];
			int srcline = 0;
			int si;

			for (si = 0; si < nsections; si++) {
				const char *bn;
				bn = strrchr(sections[si].path, '/');
				bn = bn != NULL ? bn + 1 : sections[si].path;
				if (strcmp(bn, sym->binary) == 0)
					break;
			}
			if (si < nsections) {
				dc = dwarf_cache_open(sections[si].path,
				    sym->slide);
				if (dc != NULL &&
				    dwarf_addr_to_line(dc, sym->addr,
				    srcfile, sizeof(srcfile),
				    &srcline) == 0) {
					e->source_file = strdup(srcfile);
					e->source_line = srcline;
				}
			}
		}
	}

	/*
	 * Entry at offset 0 after a CALL = function was called.
	 * Must check prev_class to avoid overcounting on sync-at-entry,
	 * tail jumps, or other non-call control flow to function starts.
	 */
	if (ip == sym->addr &&
	    (p->prev_class == ptic_call || p->prev_class == ptic_far_call)) {
		e->calls++;
		/*
		 * Push this activation.  Pushing even with tsc == 0
		 * keeps pushes and pops balanced; a zero entry stamp
		 * simply charges nothing on pop.
		 */
		if (p->act_depth < PROF_ACT_MAX) {
			p->act_ent[p->act_depth] = (int)(e - p->entries);
			p->act_tsc[p->act_depth] = tsc;
			p->act_depth++;
		} else
			p->act_overflow++;
	}

	p->prev_class = iclass;

	/* Accumulate per-call time on return. */
	switch (iclass) {
	case ptic_far_return:
		/*
		 * An IRET matching a pending ptev_async_branch
		 * (interrupt) returns to the interrupted flow, not
		 * from a call — consume the marker and skip the
		 * return accounting.
		 */
		if (p->async_depth > 0) {
			p->async_depth--;
			break;
		}
		/* FALLTHROUGH */
	case ptic_return:
		e->returns++;
		/*
		 * Pop the most recent activation and charge the entry
		 * it recorded — recursion-safe per-activation timing.
		 * Always consume the activation: a return with no
		 * usable delta must not let a later unrelated call be
		 * charged a span covering several invocations.
		 */
		if (p->act_overflow > 0)
			p->act_overflow--;
		else if (p->act_depth > 0) {
			struct profile_entry *ce;
			uint64_t entry;

			p->act_depth--;
			ce = &p->entries[p->act_ent[p->act_depth]];
			entry = p->act_tsc[p->act_depth];
			if (tsc > 0 && entry > 0 && tsc > entry)
				ce->cumulative_tsc += tsc - entry;
		}
		break;
	case ptic_jump:
	case ptic_cond_jump:
		e->branches++;
		break;
	default:
		break;
	}
}

/* ------------------------------------------------------------------ */
/* Filter helper                                                       */
/* ------------------------------------------------------------------ */

static bool
filter_matches(const struct pt_decode_opts *opts, const char *name)
{
	int i;

	if (opts == NULL || opts->nfilter_funcs == 0)
		return (true);
	if (name == NULL)
		return (false);

	for (i = 0; i < opts->nfilter_funcs; i++) {
		if (strcmp(opts->filter_funcs[i], name) == 0)
			return (true);
	}
	return (false);
}

static int
profile_cmp_calls(const void *a, const void *b)
{
	const struct profile_entry *ea = a;
	const struct profile_entry *eb = b;

	return (eb->calls - ea->calls);
}

static void
profile_print(struct profile *p, const struct pt_decode_opts *opts)
{
	bool have_tsc;
	int i;

	qsort(p->entries, p->count, sizeof(p->entries[0]), profile_cmp_calls);

	/* Check if any entry has TSC data. */
	have_tsc = false;
	for (i = 0; i < p->count; i++) {
		if (p->entries[i].cumulative_tsc > 0) {
			have_tsc = true;
			break;
		}
	}

	if (have_tsc) {
		printf("%-8s %-8s %-8s  %-14s  %-20s  %s\n",
		    "CALLS", "RETURNS", "BRANCHES", "TIME(tsc)",
		    "BINARY", "FUNCTION");
		printf("%-8s %-8s %-8s  %-14s  %-20s  %s\n",
		    "--------", "--------", "--------",
		    "--------------",
		    "--------------------", "--------------------");
	} else {
		printf("%-8s %-8s %-8s  %-20s  %s\n",
		    "CALLS", "RETURNS", "BRANCHES", "BINARY", "FUNCTION");
		printf("%-8s %-8s %-8s  %-20s  %s\n",
		    "--------", "--------", "--------",
		    "--------------------", "--------------------");
	}

	for (i = 0; i < p->count; i++) {
		struct profile_entry *e = &p->entries[i];
		if (e->calls == 0 && e->returns == 0 && e->branches == 0)
			continue;
		if (!filter_matches(opts, e->name))
			continue;
		if (have_tsc) {
			uint64_t dt = e->cumulative_tsc;
			printf("%-8d %-8d %-8d  %-14lu  %-20s  %s",
			    e->calls, e->returns, e->branches,
			    (unsigned long)dt, e->binary, e->name);
		} else {
			printf("%-8d %-8d %-8d  %-20s  %s",
			    e->calls, e->returns, e->branches,
			    e->binary, e->name);
		}
		if (e->source_file != NULL)
			printf("  (%s:%d)", e->source_file, e->source_line);
		printf("\n");
	}
}

static void
profile_free(struct profile *p)
{
	int i;

	for (i = 0; i < p->count; i++)
		free(p->entries[i].source_file);
	free(p->entries);
	p->entries = NULL;
	p->count = 0;
	p->capacity = 0;
}

/* ------------------------------------------------------------------ */
/* Call tree                                                            */
/* ------------------------------------------------------------------ */

struct ct_node {
	const char		*name;		/* borrowed from sym_table */
	const char		*binary;	/* borrowed from sym_table */
	int			count;		/* times called at this position */
	uint64_t		total_tsc;	/* accumulated TSC ticks */
	struct ct_node		*children;
	int			nchildren;
	int			children_cap;
};

struct calltree {
	struct ct_node		root;		/* virtual root */
	struct ct_node		**stack;	/* shadow call stack */
	uint64_t		*entry_tscs;	/* per-slot entry TSC (parallel
						 * to stack; recursion-safe) */
	int			depth;
	int			stack_cap;
	const struct sym_entry	*prev_sym;
	enum pt_insn_class	prev_class;
	int			async_depth;	/* pending interrupt markers */
	/*
	 * Dropped pushes (OOM).  A counter, not a position: if a later
	 * push succeeds while this is nonzero, the next return consumes
	 * the marker instead of the real innermost frame, so per-frame
	 * attribution degrades under memory pressure — but depth
	 * balance, the invariant that matters, is preserved.
	 */
	int			push_overflow;
};

static void
ct_node_init(struct ct_node *n, const char *name, const char *binary)
{

	memset(n, 0, sizeof(*n));
	n->name = name;
	n->binary = binary;
}

static struct ct_node *
ct_find_or_add_child(struct ct_node *parent, const char *name,
    const char *binary)
{
	int i;

	for (i = 0; i < parent->nchildren; i++) {
		if (parent->children[i].name == name &&
		    parent->children[i].binary == binary)
			return (&parent->children[i]);
	}

	if (parent->nchildren >= parent->children_cap) {
		int newcap = parent->children_cap == 0 ?
		    8 : parent->children_cap * 2;
		struct ct_node *newc;

		newc = realloc(parent->children,
		    newcap * sizeof(*newc));
		if (newc == NULL)
			return (NULL);
		parent->children = newc;
		parent->children_cap = newcap;
	}

	ct_node_init(&parent->children[parent->nchildren], name, binary);
	return (&parent->children[parent->nchildren++]);
}

static void
calltree_init(struct calltree *ct)
{

	memset(ct, 0, sizeof(*ct));
	ct_node_init(&ct->root, "<root>", "");
	ct->stack_cap = 256;
	ct->stack = calloc(ct->stack_cap, sizeof(*ct->stack));
	ct->entry_tscs = calloc(ct->stack_cap, sizeof(*ct->entry_tscs));
	if (ct->stack == NULL || ct->entry_tscs == NULL)
		err(1, "calltree_init");
	ct->stack[0] = &ct->root;
	ct->depth = 0;
}

static void
calltree_push(struct calltree *ct, const struct sym_entry *sym,
    uint64_t tsc)
{
	struct ct_node *parent, *child;

	if (sym == NULL)
		return;

	parent = ct->stack[ct->depth];
	child = ct_find_or_add_child(parent, sym->name, sym->binary);
	if (child == NULL) {
		/* Balance the dropped push against its future pop. */
		ct->push_overflow++;
		return;
	}
	child->count++;

	ct->depth++;
	if (ct->depth >= ct->stack_cap) {
		int newcap = ct->stack_cap * 2;
		struct ct_node **news;
		uint64_t *newt;

		news = realloc(ct->stack, newcap * sizeof(*news));
		if (news == NULL) {
			ct->depth--;
			ct->push_overflow++;
			return;
		}
		ct->stack = news;
		newt = realloc(ct->entry_tscs, newcap * sizeof(*newt));
		if (newt == NULL) {
			ct->depth--;
			ct->push_overflow++;
			return;
		}
		ct->entry_tscs = newt;
		ct->stack_cap = newcap;
	}
	ct->stack[ct->depth] = child;
	/* Per-activation entry stamp: recursion cannot clobber it. */
	ct->entry_tscs[ct->depth] = tsc;
}

static void
calltree_pop(struct calltree *ct, uint64_t tsc)
{

	if (ct->push_overflow > 0) {
		ct->push_overflow--;
		return;
	}
	if (ct->depth > 0) {
		struct ct_node *node = ct->stack[ct->depth];
		uint64_t entry = ct->entry_tscs[ct->depth];

		if (tsc > 0 && entry > 0 && tsc > entry)
			node->total_tsc += tsc - entry;
		ct->depth--;
	}
}

/*
 * Feed each decoded instruction to the call tree.
 * Push on CALL (using the callee's symbol), pop on RETURN.
 */
static void
calltree_record(struct calltree *ct, const struct sym_entry *sym,
    uint64_t ip, enum pt_insn_class iclass, uint64_t tsc)
{

	if (sym == NULL) {
		/* See collapsed_record: latch calls across PLT stubs. */
		if (iclass == ptic_call || iclass == ptic_far_call)
			ct->prev_class = iclass;
		else if (iclass == ptic_far_return && ct->async_depth > 0)
			ct->async_depth--;	/* interrupt IRET: keep latch */
		else if (iclass == ptic_return || iclass == ptic_far_return)
			ct->prev_class = ptic_error;
		return;
	}

	/*
	 * Detect function entry: the previous instruction was a CALL
	 * and we're now at offset 0 of a new symbol.
	 */
	if (ip == sym->addr &&
	    (ct->prev_class == ptic_call ||
	     ct->prev_class == ptic_far_call)) {
		calltree_push(ct, sym, tsc);
	}

	if (iclass == ptic_far_return && ct->async_depth > 0) {
		/*
		 * IRET matching a pending ptev_async_branch (interrupt):
		 * returns to the interrupted flow, so do not pop a
		 * legitimate frame.
		 */
		ct->async_depth--;
	} else if (iclass == ptic_return || iclass == ptic_far_return)
		calltree_pop(ct, tsc);

	ct->prev_sym = sym;
	ct->prev_class = iclass;
}

static int
ct_cmp_count(const void *a, const void *b)
{
	const struct ct_node *na = a;
	const struct ct_node *nb = b;

	return (nb->count - na->count);
}

static void
ct_print_node(struct ct_node *n, int indent)
{
	int i;

	/* Sort children by call count descending. */
	if (n->nchildren > 1)
		qsort(n->children, n->nchildren, sizeof(n->children[0]),
		    ct_cmp_count);

	for (i = 0; i < n->nchildren; i++) {
		struct ct_node *c = &n->children[i];
		if (c->total_tsc > 0)
			printf("%*s%s:%s  (%d) [%lu tsc]\n",
			    indent * 2, "", c->binary, c->name,
			    c->count, (unsigned long)c->total_tsc);
		else
			printf("%*s%s:%s  (%d)\n",
			    indent * 2, "", c->binary, c->name, c->count);
		ct_print_node(c, indent + 1);
	}
}

static void
calltree_print(struct calltree *ct)
{

	ct_print_node(&ct->root, 0);
}

static int
ct_node_count(struct ct_node *n)
{
	int total, i;

	total = n->nchildren;
	for (i = 0; i < n->nchildren; i++)
		total += ct_node_count(&n->children[i]);
	return (total);
}

static void
ct_node_free(struct ct_node *n)
{
	int i;

	for (i = 0; i < n->nchildren; i++)
		ct_node_free(&n->children[i]);
	free(n->children);
	n->children = NULL;
	n->nchildren = 0;
}

static void
calltree_free(struct calltree *ct)
{

	ct_node_free(&ct->root);
	free(ct->stack);
	ct->stack = NULL;
	free(ct->entry_tscs);
	ct->entry_tscs = NULL;
	ct->depth = 0;
	ct->stack_cap = 0;
}

/* ------------------------------------------------------------------ */
/* Collapsed (folded) stacks for flamegraph.pl / Speedscope            */
/* ------------------------------------------------------------------ */

#define	MAX_COLLAPSED_STACKS	4096
#define	MAX_STACK_DEPTH		256

struct collapsed_entry {
	char	*stack;		/* "func1;func2;func3" (strdup'd) */
	int	count;
};

struct collapsed {
	struct collapsed_entry	*entries;
	int			count;
	int			capacity;
	/* Current shadow call stack. */
	const char		*names[MAX_STACK_DEPTH];
	int			depth;
	int			overflow_depth;	/* pushes dropped at cap */
	int			async_depth;	/* pending interrupt markers */
	const struct sym_entry	*prev_sym;
	enum pt_insn_class	prev_class;
};

static void
collapsed_init(struct collapsed *col)
{

	memset(col, 0, sizeof(*col));
}

/*
 * Build the stack string by joining names[0..depth-1] with ";".
 * Returns a malloc'd string, or NULL on failure.
 */
static char *
collapsed_build_stack(struct collapsed *col)
{
	char buf[8192];
	int i, off;

	if (col->depth <= 0)
		return (NULL);

	off = 0;
	for (i = 0; i < col->depth; i++) {
		int n;

		if (i > 0 && off < (int)sizeof(buf) - 1)
			buf[off++] = ';';
		/*
		 * snprintf returns the would-be length, not bytes
		 * written — clamp so a deep stack of long symbol
		 * names cannot push off past the buffer.
		 */
		n = snprintf(buf + off, sizeof(buf) - off, "%s",
		    col->names[i]);
		if (n < 0 || off + n >= (int)sizeof(buf) - 1) {
			off = (int)sizeof(buf) - 1;
			break;
		}
		off += n;
	}
	buf[off] = '\0';
	return (strdup(buf));
}

/*
 * Find or create the entry for the current stack and increment it.
 */
static void
collapsed_count_stack(struct collapsed *col)
{
	char *stack;
	int i;

	stack = collapsed_build_stack(col);
	if (stack == NULL)
		return;

	/* Look for existing entry. */
	for (i = 0; i < col->count; i++) {
		if (strcmp(col->entries[i].stack, stack) == 0) {
			col->entries[i].count++;
			free(stack);
			return;
		}
	}

	/* Add new entry. */
	if (col->count >= col->capacity) {
		int newcap = col->capacity == 0 ?
		    256 : col->capacity * 2;
		struct collapsed_entry *newent;

		if (newcap > MAX_COLLAPSED_STACKS)
			newcap = MAX_COLLAPSED_STACKS;
		if (col->count >= newcap) {
			static bool warned;
			if (!warned) {
				warnx("collapsed stacks: hit %d unique "
				    "stack limit, dropping new stacks",
				    MAX_COLLAPSED_STACKS);
				warned = true;
			}
			free(stack);
			return;
		}
		newent = realloc(col->entries,
		    newcap * sizeof(*newent));
		if (newent == NULL) {
			free(stack);
			return;
		}
		col->entries = newent;
		col->capacity = newcap;
	}

	col->entries[col->count].stack = stack;
	col->entries[col->count].count = 1;
	col->count++;
}

/*
 * Feed each decoded instruction to the collapsed stack tracker.
 * Push on CALL (function entry at offset 0), count+pop on RETURN.
 *
 * Counting on RETURN (not PUSH) gives correct flamegraph semantics:
 * a call chain main→foo→bar produces one sample at "main;foo;bar"
 * instead of three separate prefix samples.
 */
static void
collapsed_record(struct collapsed *col, const struct sym_entry *sym,
    uint64_t ip, enum pt_insn_class iclass)
{

	if (sym == NULL) {
		/*
		 * PLT stubs and other unsymbolized code: a call
		 * latches, a return clears, and jumps (the PLT's
		 * jmp *GOT) preserve the latch so the eventual
		 * callee entry is still recognized as called.
		 */
		if (iclass == ptic_call || iclass == ptic_far_call)
			col->prev_class = iclass;
		else if (iclass == ptic_far_return && col->async_depth > 0)
			col->async_depth--;	/* interrupt IRET: keep latch */
		else if (iclass == ptic_return || iclass == ptic_far_return)
			col->prev_class = ptic_error;
		return;
	}

	if (ip == sym->addr &&
	    (col->prev_class == ptic_call ||
	     col->prev_class == ptic_far_call)) {
		if (col->depth < MAX_STACK_DEPTH) {
			col->names[col->depth] = sym->name;
			col->depth++;
		} else {
			/* Balance the dropped push against its pop. */
			col->overflow_depth++;
		}
	}

	if (iclass == ptic_return || iclass == ptic_far_return) {
		if (iclass == ptic_far_return && col->async_depth > 0) {
			/*
			 * IRET matching a pending ptev_async_branch
			 * (interrupt): not a function return, so do not
			 * count or pop.
			 */
			col->async_depth--;
		} else if (col->overflow_depth > 0) {
			col->overflow_depth--;
		} else {
			collapsed_count_stack(col);
			if (col->depth > 0)
				col->depth--;
		}
	}

	col->prev_sym = sym;
	col->prev_class = iclass;
}

static int
collapsed_cmp_count(const void *a, const void *b)
{
	const struct collapsed_entry *ea = a;
	const struct collapsed_entry *eb = b;

	return (eb->count - ea->count);
}

static bool
collapsed_stack_matches(const char *stack, const struct pt_decode_opts *opts)
{
	char *s, *tok, *saveptr;

	if (opts == NULL || opts->nfilter_funcs == 0)
		return (true);

	s = strdup(stack);
	if (s == NULL)
		return (true);	/* fail open: show the stack */
	tok = strtok_r(s, ";", &saveptr);
	while (tok != NULL) {
		/* tok may be "binary:func" — check the func part. */
		const char *colon = strrchr(tok, ':');
		const char *name = colon != NULL ? colon + 1 : tok;
		if (filter_matches(opts, name)) {
			free(s);
			return (true);
		}
		tok = strtok_r(NULL, ";", &saveptr);
	}
	free(s);
	return (false);
}

static void
collapsed_print(struct collapsed *col, const struct pt_decode_opts *opts)
{

	qsort(col->entries, col->count, sizeof(col->entries[0]),
	    collapsed_cmp_count);

	for (int i = 0; i < col->count; i++) {
		if (!collapsed_stack_matches(col->entries[i].stack, opts))
			continue;
		printf("%s %d\n", col->entries[i].stack,
		    col->entries[i].count);
	}
}

static void
collapsed_free(struct collapsed *col)
{
	int i;

	for (i = 0; i < col->count; i++)
		free(col->entries[i].stack);
	free(col->entries);
	col->entries = NULL;
	col->count = 0;
	col->capacity = 0;
}

/* ------------------------------------------------------------------ */
/* Speedscope JSON export                                              */
/* ------------------------------------------------------------------ */

/* Lookup-only variant for phase 2: shared.frames is already emitted. */
static int
speedscope_frame_find(char **frames, int nframes, const char *name)
{
	int i;

	for (i = 0; i < nframes; i++)
		if (strcmp(frames[i], name) == 0)
			return (i);
	return (-1);
}

static int
speedscope_frame_idx(char ***frames, int *nframes, int *cap,
    const char *name)
{
	char *dup;
	int i;

	for (i = 0; i < *nframes; i++) {
		if (strcmp((*frames)[i], name) == 0)
			return (i);
	}
	if (*nframes >= *cap) {
		int newcap = *cap == 0 ? 64 : *cap * 2;
		char **newf;

		newf = realloc(*frames, newcap * sizeof(char *));
		if (newf == NULL)
			return (-1);
		*frames = newf;
		*cap = newcap;
	}
	dup = strdup(name);
	if (dup == NULL)
		return (-1);
	(*frames)[*nframes] = dup;
	return ((*nframes)++);
}

static void
speedscope_print(struct collapsed *col)
{
	char **frames;
	int nframes, frames_cap;
	char escaped[256 * 6 + 1];
	int i, j;

	frames = NULL;
	nframes = 0;
	frames_cap = 0;

	printf("{\n");
	printf("  \"$schema\": \"https://www.speedscope.app/"
	    "file-format-spec.json\",\n");

	/* Phase 1: collect unique frames from all stacks. */
	for (i = 0; i < col->count; i++) {
		char *s, *tok, *saveptr;
		s = strdup(col->entries[i].stack);
		if (s == NULL)
			continue;
		tok = strtok_r(s, ";", &saveptr);
		while (tok != NULL) {
			speedscope_frame_idx(&frames, &nframes,
			    &frames_cap, tok);
			tok = strtok_r(NULL, ";", &saveptr);
		}
		free(s);
	}

	/* Emit shared frames. */
	printf("  \"shared\": {\"frames\": [\n");
	for (i = 0; i < nframes; i++) {
		json_escape(escaped, sizeof(escaped), frames[i]);
		printf("    {\"name\": \"%s\"}%s\n",
		    escaped, i < nframes - 1 ? "," : "");
	}
	printf("  ]},\n");

	/* Phase 2: build samples and weights. */
	printf("  \"profiles\": [{\n");
	printf("    \"type\": \"sampled\",\n");
	printf("    \"name\": \"bsdtrace\",\n");
	printf("    \"unit\": \"none\",\n");
	printf("    \"startValue\": 0,\n");

	long total_weight = 0;
	for (i = 0; i < col->count; i++)
		total_weight += col->entries[i].count;
	printf("    \"endValue\": %ld,\n", total_weight);

	printf("    \"samples\": [\n");
	for (i = 0; i < col->count; i++) {
		char *s, *tok, *saveptr;
		printf("      [");
		s = strdup(col->entries[i].stack);
		if (s == NULL) {
			/* Keep the JSON well-formed: emit an empty sample. */
			printf("]%s\n", i < col->count - 1 ? "," : "");
			continue;
		}
		tok = strtok_r(s, ";", &saveptr);
		j = 0;
		while (tok != NULL) {
			int idx = speedscope_frame_find(frames, nframes,
			    tok);
			if (idx >= 0) {
				if (j > 0)
					printf(",");
				printf("%d", idx);
				j++;
			}
			tok = strtok_r(NULL, ";", &saveptr);
		}
		free(s);
		printf("]%s\n", i < col->count - 1 ? "," : "");
	}
	printf("    ],\n");

	printf("    \"weights\": [");
	for (i = 0; i < col->count; i++) {
		printf("%d%s", col->entries[i].count,
		    i < col->count - 1 ? "," : "");
	}
	printf("]\n");
	printf("  }],\n");
	printf("  \"name\": \"bsdtrace trace\",\n");
	printf("  \"exporter\": \"bsdtrace\"\n");
	printf("}\n");

	for (i = 0; i < nframes; i++)
		free(frames[i]);
	free(frames);
}

/* ------------------------------------------------------------------ */
/* Caller/callee view                                                  */
/* ------------------------------------------------------------------ */

struct caller_edge {
	const char	*name;
	const char	*binary;
	int		count;
	uint64_t	tsc;
};

struct func_summary {
	const char	*name;
	const char	*binary;
	int		total_calls;
	uint64_t	total_tsc;
	struct caller_edge *callers;
	int		ncallers;
	int		callers_cap;
	struct caller_edge *callees;
	int		ncallees;
	int		callees_cap;
};

static struct func_summary *
callers_find_or_add(struct func_summary **funcs, int *nfuncs, int *cap,
    const char *name, const char *binary)
{
	int i;
	struct func_summary *f;

	for (i = 0; i < *nfuncs; i++) {
		if (strcmp((*funcs)[i].name, name) == 0 &&
		    strcmp((*funcs)[i].binary, binary) == 0)
			return (&(*funcs)[i]);
	}
	if (*nfuncs >= *cap) {
		int newcap = *cap == 0 ? 64 : *cap * 2;
		struct func_summary *newf;

		newf = realloc(*funcs, newcap * sizeof(struct func_summary));
		if (newf == NULL)
			return (NULL);
		*funcs = newf;
		*cap = newcap;
	}
	f = &(*funcs)[*nfuncs];
	memset(f, 0, sizeof(*f));
	f->name = name;
	f->binary = binary;
	(*nfuncs)++;
	return (f);
}

static void
callers_add_edge(struct caller_edge **edges, int *n, int *cap,
    const char *name, const char *binary, int count, uint64_t tsc)
{
	int i;

	for (i = 0; i < *n; i++) {
		if (strcmp((*edges)[i].name, name) == 0 &&
		    strcmp((*edges)[i].binary, binary) == 0) {
			(*edges)[i].count += count;
			(*edges)[i].tsc += tsc;
			return;
		}
	}
	if (*n >= *cap) {
		int newcap = *cap == 0 ? 16 : *cap * 2;
		struct caller_edge *newe;

		newe = realloc(*edges, newcap * sizeof(struct caller_edge));
		if (newe == NULL)
			return;
		*edges = newe;
		*cap = newcap;
	}
	(*edges)[*n].name = name;
	(*edges)[*n].binary = binary;
	(*edges)[*n].count = count;
	(*edges)[*n].tsc = tsc;
	(*n)++;
}

static void
ct_collect_edges(struct ct_node *parent, struct ct_node *node,
    struct func_summary **funcs, int *nfuncs, int *cap)
{
	struct func_summary *f;
	int i;

	if (node->name != NULL) {
		f = callers_find_or_add(funcs, nfuncs, cap,
		    node->name, node->binary ? node->binary : "???");
		if (f != NULL) {
			f->total_calls += node->count;
			f->total_tsc += node->total_tsc;

			if (parent != NULL && parent->name != NULL)
				callers_add_edge(&f->callers, &f->ncallers,
				    &f->callers_cap,
				    parent->name,
				    parent->binary ? parent->binary : "???",
				    node->count, node->total_tsc);
		}
	}

	for (i = 0; i < node->nchildren; i++) {
		struct ct_node *child = &node->children[i];
		if (node->name != NULL && child->name != NULL) {
			struct func_summary *pf;
			pf = callers_find_or_add(funcs, nfuncs, cap,
			    node->name,
			    node->binary ? node->binary : "???");
			if (pf != NULL)
				callers_add_edge(&pf->callees, &pf->ncallees,
				    &pf->callees_cap,
				    child->name,
				    child->binary ? child->binary : "???",
				    child->count, child->total_tsc);
		}
		ct_collect_edges(node, child, funcs, nfuncs, cap);
	}
}

static int
callers_cmp(const void *a, const void *b)
{
	const struct func_summary *fa = a, *fb = b;
	return (fb->total_calls - fa->total_calls);
}

static int
edge_cmp(const void *a, const void *b)
{
	const struct caller_edge *ea = a, *eb = b;
	return (eb->count - ea->count);
}

static void
callers_print(struct calltree *ct, const struct pt_decode_opts *opts)
{
	struct func_summary *funcs;
	int nfuncs, funcs_cap;
	int i, j;

	funcs = NULL;
	nfuncs = 0;
	funcs_cap = 0;

	/*
	 * Walk from the root's children so the virtual <root> node is
	 * neither summarized nor listed as anyone's caller.
	 */
	for (i = 0; i < ct->root.nchildren; i++)
		ct_collect_edges(NULL, &ct->root.children[i], &funcs,
		    &nfuncs, &funcs_cap);
	qsort(funcs, nfuncs, sizeof(struct func_summary), callers_cmp);

	for (i = 0; i < nfuncs; i++) {
		struct func_summary *f = &funcs[i];

		if (!filter_matches(opts, f->name))
			continue;

		printf("--- %s:%s  (%d calls",
		    f->binary, f->name, f->total_calls);
		if (f->total_tsc > 0)
			printf(", %lu tsc",
			    (unsigned long)f->total_tsc);
		printf(")\n");

		if (f->ncallers > 0) {
			qsort(f->callers, f->ncallers,
			    sizeof(struct caller_edge), edge_cmp);
			printf("  called by:\n");
			for (j = 0; j < f->ncallers; j++)
				printf("    %s:%s  (%d)\n",
				    f->callers[j].binary,
				    f->callers[j].name,
				    f->callers[j].count);
		}

		if (f->ncallees > 0) {
			qsort(f->callees, f->ncallees,
			    sizeof(struct caller_edge), edge_cmp);
			printf("  calls:\n");
			for (j = 0; j < f->ncallees; j++)
				printf("    %s:%s  (%d)\n",
				    f->callees[j].binary,
				    f->callees[j].name,
				    f->callees[j].count);
		}
		printf("\n");
	}

	for (i = 0; i < nfuncs; i++) {
		free(funcs[i].callers);
		free(funcs[i].callees);
	}
	free(funcs);
}

/* ------------------------------------------------------------------ */
/* Instruction decoder                                                 */
/* ------------------------------------------------------------------ */

/*
 * Reset the aggregate-view flow trackers at a trace discontinuity
 * (overflow, non-resumed enable): clear the call latches, unwind the
 * shadow stacks without counting (entry stamps are stale), and drop
 * pending interrupt markers, which cannot meaningfully survive the
 * gap.  Plain disable/resume pairs are contiguous flow and must NOT
 * reset anything — see the ptev_disabled case in the event drain.
 */
static void
flow_reset(struct profile *prof, struct calltree *ct, struct collapsed *col)
{

	prof->prev_class = ptic_error;
	ct->prev_class = ptic_error;
	col->prev_class = ptic_error;

	/* Unwind without counting; entry stamps are stale. */
	ct->push_overflow = 0;
	while (ct->depth > 0)
		calltree_pop(ct, 0);
	col->depth = 0;
	col->overflow_depth = 0;
	prof->act_depth = 0;
	prof->act_overflow = 0;
	/* Pending interrupt markers did not survive the gap. */
	prof->async_depth = 0;
	ct->async_depth = 0;
	col->async_depth = 0;
}

int
decode_pt_insn(const void *buf, size_t len,
    const struct pt_image_info *sections, int nsections,
    enum bsdtrace_fmt fmt, const struct pt_decode_opts *opts)
{
	struct pt_config config;
	struct pt_insn_decoder *decoder;
	struct pt_image *image;
	struct sym_table st;
	struct bin_range ranges[MAX_BIN_RANGES];
	int nranges;
	struct profile prof;
	struct calltree ct;
	struct collapsed col;
	struct pt_insn insn;
	const struct sym_entry *sym;
	const char *bn;
	const char *label;
	const char *syscall_name;
	uint64_t boff;
	uint64_t tsc, last_sync;
	uint32_t lost_mtc, lost_cyc;
	int tid;
	int status;
	uint64_t total, calls, branches, returns, syscalls, nomaps, errors;
	int ovf_count;
	uint32_t total_lost_mtc, total_lost_cyc;

	if (buf == NULL || len == 0) {
		warnx("no PT data to decode");
		return (-1);
	}

	if (nsections <= 0) {
		if (fmt == FMT_TEXT || fmt == FMT_JSON) {
			warnx("no image sections — falling back to packet decode");
			return (decode_pt_buffer(buf, len, fmt));
		}
		warnx("no image sections — cannot produce %s output",
		    fmt == FMT_PROFILE ? "profile" :
		    fmt == FMT_TREE ? "tree" :
		    fmt == FMT_COLLAPSED ? "collapsed" :
		    fmt == FMT_SPEEDSCOPE ? "speedscope" :
		    fmt == FMT_CALLERS ? "callers" : "aggregate");
		return (-1);
	}

	sym_table_init(&st);
	profile_init(&prof);
	calltree_init(&ct);
	collapsed_init(&col);

	image = build_pt_image(sections, nsections, &st, true);
	if (image == NULL) {
		collapsed_free(&col);
		calltree_free(&ct);
		profile_free(&prof);
		sym_table_free(&st);
		warnx("image build failed — falling back to packet decode");
		return (decode_pt_buffer(buf, len, fmt));
	}

	nranges = build_bin_ranges(sections, nsections, ranges,
	    MAX_BIN_RANGES);

	pt_config_init(&config);
	config.begin = __DECONST(uint8_t *, buf);
	config.end = __DECONST(uint8_t *, buf) + len;
	tid = opts != NULL ? opts->tid : -1;

	config_apply_env(&config, opts);
	if (opts != NULL && opts->mtc_freq > 0) {
		config.mtc_freq = opts->mtc_freq;
		config.flags.variant.insn.enable_tick_events = 1;
	}

	decoder = pt_insn_alloc_decoder(&config);
	if (decoder == NULL) {
		warnx("pt_insn_alloc_decoder failed");
		pt_image_free(image);
		collapsed_free(&col);
		calltree_free(&ct);
		profile_free(&prof);
		sym_table_free(&st);
		return (-1);
	}

	status = pt_insn_set_image(decoder, image);
	if (status < 0) {
		warnx("pt_insn_set_image failed: %s",
		    pt_errstr(pt_errcode(status)));
		pt_insn_free_decoder(decoder);
		pt_image_free(image);
		collapsed_free(&col);
		calltree_free(&ct);
		profile_free(&prof);
		sym_table_free(&st);
		return (-1);
	}

	if (fmt == FMT_TEXT) {
		if (tid >= 0)
			fprintf(stderr,
			    "\nPT Instructions (%zu bytes, tid=%d)\n"
			    "────────────────────────────────────────\n",
			    len, tid);
		else
			fprintf(stderr,
			    "\nPT Instructions (%zu bytes)\n"
			    "────────────────────────────────────────\n",
			    len);
	}

	total = 0;
	calls = 0;
	branches = 0;
	returns = 0;
	syscalls = 0;
	nomaps = 0;
	errors = 0;
	ovf_count = 0;
	total_lost_mtc = 0;
	total_lost_cyc = 0;

	last_sync = 0;
	status = resync_forward(decoder, &last_sync);
	while (status >= 0) {
		while (status & pts_event_pending) {
			struct pt_event ev;
			status = pt_insn_event(decoder, &ev, sizeof(ev));
			if (status < 0)
				break;
			switch (ev.type) {
			case ptev_overflow:
				ovf_count++;
				/* Trace data was lost: full discontinuity. */
				flow_reset(&prof, &ct, &col);
				break;
			case ptev_enabled:
				if (fmt == FMT_TEXT)
					printf("  [%s]\n",
					    ev.variant.enabled.resumed ?
					    "resumed" : "enabled");
				else if (fmt == FMT_JSON)
					printf("{\"event\":\"%s\"}\n",
					    ev.variant.enabled.resumed ?
					    "resumed" : "enabled");
				/*
				 * A resume continues the flow suspended at
				 * the matching disable; a plain enable
				 * starts a new, unrelated flow.
				 */
				if (!ev.variant.enabled.resumed)
					flow_reset(&prof, &ct, &col);
				break;
			case ptev_disabled:
			case ptev_async_disabled:
				if (fmt == FMT_TEXT)
					printf("  [disabled]\n");
				else if (fmt == FMT_JSON)
					printf("{\"event\":\"disabled\"}\n");
				/*
				 * No state reset here: a resumed
				 * enable continues contiguous flow,
				 * and an async disable can land
				 * between a CALL and its target's
				 * first instruction — clearing the
				 * call latch there would miss the
				 * push while the matching return
				 * still pops, skewing every later
				 * frame.  Real discontinuities are
				 * handled by the non-resumed-enable
				 * and overflow resets.
				 */
				break;
			case ptev_async_branch:
				/*
				 * Interrupt: push a marker so that the
				 * matching IRET (ptic_far_return) does not
				 * pop a legitimate frame in the aggregate
				 * views (relevant for -K kernel traces).
				 */
				prof.async_depth++;
				ct.async_depth++;
				col.async_depth++;
				break;
			case ptev_ptwrite:
				/* ip is valid only when !ip_suppressed. */
				if (fmt == FMT_JSON) {
					if (ev.ip_suppressed)
						printf("{\"ptwrite\":\"0x%lx\"}\n",
						    (unsigned long)ev.variant.ptwrite.payload);
					else
						printf("{\"ptwrite\":\"0x%lx\","
						    "\"ip\":\"0x%lx\"}\n",
						    (unsigned long)ev.variant.ptwrite.payload,
						    (unsigned long)ev.variant.ptwrite.ip);
				} else if (fmt == FMT_TEXT) {
					if (ev.ip_suppressed)
						printf("  PTWRITE   0x%016lx\n",
						    (unsigned long)ev.variant.ptwrite.payload);
					else
						printf("  PTWRITE   0x%016lx  ip=0x%lx\n",
						    (unsigned long)ev.variant.ptwrite.payload,
						    (unsigned long)ev.variant.ptwrite.ip);
				}
				break;
			default:
				break;
			}
		}
		if (status < 0) {
			/*
			 * Event decode errors mid-trace (bad query on a
			 * lossy or wrapped stream) are recoverable —
			 * count them and resync like the pt_insn_next
			 * error path instead of abandoning the rest of
			 * the buffer.
			 */
			if (status == -pte_eos)
				break;
			errors++;
			status = resync_forward(decoder, &last_sync);
			continue;
		}

		/*
		 * End of trace: without this check libipt keeps
		 * following direct branches statically past the last
		 * packet, appending phantom instructions (and a
		 * `jmp .` at the truncation point would spin forever).
		 */
		if (status & pts_eos)
			break;

		status = pt_insn_next(decoder, &insn, sizeof(insn));
		if (status < 0) {
			if (status == -pte_eos)
				break;

			if (status == -pte_nomap)
				nomaps++;
			else
				errors++;

			status = resync_forward(decoder, &last_sync);
			continue;
		}

		/* Extract timing — tsc stays 0 if unavailable. */
		tsc = 0;
		lost_mtc = 0;
		lost_cyc = 0;
		pt_insn_time(decoder, &tsc, &lost_mtc, &lost_cyc);
		/*
		 * pt_insn_time reports the decoder's running loss
		 * counters (reset at each TSC packet), not deltas —
		 * track the maximum per epoch, don't sum every insn.
		 */
		if (lost_mtc > total_lost_mtc)
			total_lost_mtc = lost_mtc;
		if (lost_cyc > total_lost_cyc)
			total_lost_cyc = lost_cyc;

		total++;
		label = insn_class_str(insn.iclass);

		switch (insn.iclass) {
		case ptic_call:
			calls++;
			break;
		case ptic_jump:
		case ptic_cond_jump:
			branches++;
			break;
		case ptic_return:
			returns++;
			break;
		case ptic_far_call:
			syscalls++;
			break;
		case ptic_far_return:
		case ptic_far_jump:
			break;
		default:
			break;
		}

		/*
		 * Profile/tree/collapsed modes need every instruction
		 * (including ptic_other) to detect function entries
		 * at offset 0.
		 */
		if (fmt == FMT_PROFILE || fmt == FMT_TREE ||
		    fmt == FMT_COLLAPSED || fmt == FMT_SPEEDSCOPE ||
		    fmt == FMT_CALLERS) {
			sym = sym_table_lookup(&st, insn.ip);
			if (fmt == FMT_PROFILE)
				profile_record(&prof, sym, insn.ip,
				    insn.iclass, tsc, sections, nsections);
			else if (fmt == FMT_TREE || fmt == FMT_CALLERS)
				calltree_record(&ct, sym, insn.ip,
				    insn.iclass, tsc);
			else
				collapsed_record(&col, sym, insn.ip,
				    insn.iclass);
			continue;
		}

		if (label == NULL)
			continue;

		sym = sym_table_lookup(&st, insn.ip);

		if (!filter_matches(opts, sym != NULL ? sym->name : NULL))
			continue;

		bn = NULL;
		boff = 0;
		if (sym == NULL)
			bn = find_binary_for_ip(ranges, nranges, insn.ip,
			    &boff);

		/*
		 * Syscall name resolution: libsys wrappers are named
		 * __sys_write, __sys_read, etc.  Extract the syscall
		 * name for display alongside the full symbol.
		 */
#define	SYSCALL_PREFIX	"__sys_"
		syscall_name = NULL;
		if (insn.iclass == ptic_far_call && sym != NULL &&
		    strncmp(sym->name, SYSCALL_PREFIX,
		    sizeof(SYSCALL_PREFIX) - 1) == 0)
			syscall_name = sym->name +
			    sizeof(SYSCALL_PREFIX) - 1;

		if (fmt == FMT_JSON) {
			if (sym != NULL) {
				char esym[256], ebin[256];
				json_escape(esym, sizeof(esym), sym->name);
				json_escape(ebin, sizeof(ebin), sym->binary);
				printf("{\"insn\":\"%s\",\"ip\":\"0x%lx\","
				    "\"sym\":\"%s\",\"off\":%lu,"
				    "\"bin\":\"%s\"",
				    label,
				    (unsigned long)insn.ip,
				    esym,
				    (unsigned long)(insn.ip - sym->addr),
				    ebin);
				if (syscall_name != NULL) {
					char esc[256];
					json_escape(esc, sizeof(esc),
					    syscall_name);
					printf(",\"syscall\":\"%s\"", esc);
				}
			} else if (bn != NULL) {
				char ebin[256];
				json_escape(ebin, sizeof(ebin), bn);
				printf("{\"insn\":\"%s\",\"ip\":\"0x%lx\","
				    "\"off\":%lu,\"bin\":\"%s\"",
				    label,
				    (unsigned long)insn.ip,
				    (unsigned long)boff,
				    ebin);
			} else {
				printf("{\"insn\":\"%s\",\"ip\":\"0x%lx\"",
				    label,
				    (unsigned long)insn.ip);
			}
			if (tsc > 0)
				printf(",\"tsc\":%lu",
				    (unsigned long)tsc);
			if (tid >= 0)
				printf(",\"tid\":%d", tid);
			printf("}\n");
		} else {
			if (sym != NULL) {
				uint64_t off = insn.ip - sym->addr;
				if (syscall_name != NULL) {
					if (off == 0)
						printf("  %-9s %s (%s:%s)\n",
						    label, syscall_name,
						    sym->binary, sym->name);
					else
						printf("  %-9s %s (%s:%s+0x%lx)\n",
						    label, syscall_name,
						    sym->binary, sym->name,
						    (unsigned long)off);
				} else if (off == 0) {
					printf("  %-9s %s:%s\n",
					    label, sym->binary,
					    sym->name);
				} else {
					printf("  %-9s %s:%s+0x%lx\n",
					    label, sym->binary,
					    sym->name,
					    (unsigned long)off);
				}
			} else {
				if (bn != NULL)
					printf("  %-9s %s+0x%lx\n",
					    label, bn,
					    (unsigned long)boff);
				else
					printf("  %-9s 0x%016lx\n",
					    label,
					    (unsigned long)insn.ip);
			}
		}
	}

	pt_insn_free_decoder(decoder);
	pt_image_free(image);

	if (fmt == FMT_PROFILE) {
		if (tid >= 0)
			printf("Thread %d:\n", tid);
		profile_print(&prof, opts);
		fprintf(stderr,
		    "%ju instructions, %d functions profiled\n",
		    (uintmax_t)total, prof.count);
	} else if (fmt == FMT_TREE) {
		if (tid >= 0)
			printf("Thread %d:\n", tid);
		calltree_print(&ct);
		fprintf(stderr,
		    "%ju instructions, %d call tree nodes\n",
		    (uintmax_t)total, ct_node_count(&ct.root));
	} else if (fmt == FMT_COLLAPSED) {
		if (tid >= 0)
			fprintf(stderr, "Thread %d:\n", tid);
		collapsed_print(&col, opts);
		fprintf(stderr,
		    "%ju instructions, %d unique stacks\n",
		    (uintmax_t)total, col.count);
	} else if (fmt == FMT_SPEEDSCOPE) {
		speedscope_print(&col);
		fprintf(stderr,
		    "%ju instructions, %d unique stacks\n",
		    (uintmax_t)total, col.count);
	} else if (fmt == FMT_CALLERS) {
		if (tid >= 0)
			printf("Thread %d:\n", tid);
		callers_print(&ct, opts);
		fprintf(stderr,
		    "%ju instructions, %d call tree nodes\n",
		    (uintmax_t)total, ct_node_count(&ct.root));
	} else if (fmt == FMT_TEXT) {
		fflush(stdout);
		fprintf(stderr,
		    "%ju instructions, %ju calls, %ju returns, "
		    "%ju branches, %ju farcalls, %ju nomap, %ju errors\n",
		    (uintmax_t)total, (uintmax_t)calls, (uintmax_t)returns,
		    (uintmax_t)branches, (uintmax_t)syscalls,
		    (uintmax_t)nomaps, (uintmax_t)errors);
	}

	if (errors > 0)
		fprintf(stderr,
		    "warning: decoder encountered %ju error(s) — "
		    "possible PT buffer wrap/overflow or truncated trace\n",
		    (uintmax_t)errors);
	if (ovf_count > 0)
		fprintf(stderr,
		    "warning: %d overflow event(s) — trace data was lost\n",
		    ovf_count);
	if (total_lost_mtc > 0 || total_lost_cyc > 0)
		fprintf(stderr,
		    "warning: lost timing packets — mtc=%u cyc=%u\n",
		    total_lost_mtc, total_lost_cyc);

	collapsed_free(&col);
	calltree_free(&ct);
	profile_free(&prof);
	sym_table_free(&st);
	dwarf_cache_close_all();
	return (total > 0 ? 0 : -1);
}
