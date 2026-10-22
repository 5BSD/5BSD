/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The program verifier (dt_prog_verify) as a tamper gate, checked by
 * exhaustive single-byte mutation of serialized programs.
 *
 * Each program P is compiled and linked with hypertrace_link(), as dtrace(1)
 * does before verification.  The harness then writes P's HyperTrace ELF, then for every
 * byte of the file and three XOR masks writes a mutant, parses it
 * (dtrace_elf_parse; plain ELF carries no checksum, and an unkeyed checksum
 * would not stop a malicious peer anyway) and, when parsing succeeds, asks
 * dt_prog_verify(P, mutant).  The oracle is dtrace_program_compiled_digest(),
 * a hash of the stripped DOF with process-local fields cleared: an accepted
 * mutant must have P's digest.  Accepting a mutant with a different digest,
 * or one whose digest cannot be computed, is a violation.  The unmodified
 * file must parse and verify, and P must verify against itself.
 *
 * Each program runs in a forked child so that a crash is reported with the
 * mutation that caused it.  The driver classifies each accepted mutant
 * with a different digest by the ELF field it changed.
 */

#include <dt_impl.h>
#include <dt_program.h>

#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *const programs[] = {
	"BEGIN { trace(1); }",
	"BEGIN /timestamp != 0/ { x = timestamp; trace(x + 3); }",
	"BEGIN { printf(\"%d %s\\n\", 42, \"text\"); }",
	"BEGIN { @c[1, \"k\"] = count(); @s = sum(7); printa(\"%d %s %@d\\n\", @c); }",
	"BEGIN { self->t = 1; this->c = self->t + 2; trace(this->c); } "
	    "END { exit(0); }",
	"BEGIN { trace(strlen(\"abc\")); trace(\"string\"); }",
};

static unsigned long accepted_same, rejected, parse_failed, violations;
static unsigned long digest_failures;
static int current;

static int
write_file(const char *path, const unsigned char *buf, size_t len)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

	if (fd < 0 || write(fd, buf, len) != (ssize_t)len) {
		perror(path);
		exit(3);
	}
	lseek(fd, 0, SEEK_SET);
	return (fd);
}

static int
check_one(dtrace_hdl_t *dtp, dtrace_prog_t *p, const uint8_t want[32],
    const char *path, const unsigned char *buf, size_t len, long offset,
    int mask)
{
	char msg[512];
	int err, fd, v, ok;
	dtrace_prog_t *q;
	uint8_t got[32];
	void *ctx;

	fd = write_file(path, buf, len);
	q = dtrace_elf_parse(dtp, fd, path, 0, &err, msg, NULL);
	close(fd);
	if (q == NULL) {
		parse_failed++;
		return (offset < 0 ? -1 : 0);
	}
	ctx = dt_verictx_init(dtp);
	v = dt_prog_verify(ctx, p, q);
	dt_verictx_teardown(ctx);
	if (v != 0) {
		rejected++;
		dt_program_destroy(dtp, q);
		return (offset < 0 ? -1 : 0);
	}
	ok = dtrace_program_compiled_digest(dtp, q, got) == 0;
	if (!ok)
		digest_failures++;
	if (!ok || memcmp(got, want, 32) != 0) {
		violations++;
		dprintf(STDOUT_FILENO, "VIOLATION program %d offset %ld mask 0x%02x: accepted "
		    "%s\n", current, offset, mask, ok ? "with a different digest" :
		    "without a digest");
	} else {
		accepted_same++;
	}
	dt_program_destroy(dtp, q);
	return (0);
}

static int
run_program(int index)
{
	static const int masks[] = { 0x01, 0x80, 0xff };
	char path[64], ok_path[64];
	unsigned char *buf, *mut;
	uint8_t want[32];
	dtrace_hdl_t *dtp;
	dtrace_prog_t *p;
	struct stat sb;
	size_t len, i;
	int err, fd, m;
	char msg[512];
	void *ctx;

	/* Kernel CTF (read from /boot) is needed to link subroutine calls. */
	current = index;
	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV, &err);
	if (dtp == NULL)
		return (2);
	p = dtrace_program_strcompile(dtp, programs[index],
	    DTRACE_PROBESPEC_NAME, 0, 0, NULL);
	if (p == NULL) {
		dprintf(STDOUT_FILENO, "compile %d: %s\n", index,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (2);
	}
	/* As dtrace(1) does: link with the HyperTrace linker, then verify. */
	if (hypertrace_link(dtp, p, msg) != 0) {
		dprintf(STDOUT_FILENO, "link %d: %s\n", index, msg);
		return (2);
	}
	snprintf(ok_path, sizeof (ok_path), "program-%d.elf", index);
	fd = open(ok_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || dtrace_elf_create(dtp, p, ELFDATA2LSB, fd, ok_path,
	    msg) != 0 || fstat(fd, &sb) != 0)
		return (2);
	/* The reference digest is taken from the program as serialized. */
	if (dtrace_program_compiled_digest(dtp, p, want) != 0)
		return (2);
	len = sb.st_size;
	buf = malloc(len);
	mut = malloc(len);
	if (buf == NULL || mut == NULL || pread(fd, buf, len, 0) !=
	    (ssize_t)len)
		return (2);
	close(fd);

	/* P verifies against itself, and the unmodified file round-trips. */
	ctx = dt_verictx_init(dtp);
	if (dt_prog_verify(ctx, p, p) != 0) {
		dprintf(STDOUT_FILENO, "program %d: self-verification failed\n", index);
		return (1);
	}
	dt_verictx_teardown(ctx);
	snprintf(path, sizeof (path), "mutant-%d.elf", index);
	if (check_one(dtp, p, want, path, buf, len, -1, 0) != 0 ||
	    accepted_same != 1) {
		dprintf(STDOUT_FILENO, "program %d: unmodified ELF not accepted\n", index);
		return (1);
	}

	for (i = 0; i < len; i++) {
		for (m = 0; m < 3; m++) {
			memcpy(mut, buf, len);
			mut[i] ^= masks[m];
			check_one(dtp, p, want, path, mut, len, (long)i,
			    masks[m]);
		}
	}
	dprintf(STDOUT_FILENO, "program %d: %zu bytes, %lu mutants accepted unchanged, "
	    "%lu rejected by the verifier, %lu refused by the parser, "
	    "%lu violations\n", index, len, accepted_same - 1, rejected,
	    parse_failed, violations);
	unlink(path);
	dtrace_close(dtp);
	return (0);
}


extern int dt_prog_verify_difo(void *, dtrace_difo_t *, dtrace_difo_t *,
    char *, char *);

/*
 * Return-type mutants on a DIFO whose host return type is DIF_TYPE_BOTTOM
 * (unresolved on the host; the guest's linker resolves it).  Expected
 * verdicts follow HyperTraceLinker::relocateRet: BOTTOM stays unchanged
 * apart from the CTF_BOTTOM_TYPE marker, STRING adds DIF_TF_BYREF, CTF keeps
 * the flags (BYREF may be added for arrays) with a register-sized by-value
 * size, or is exactly the void/int(exit) return type.  Prints one line per
 * mutant: "bottom-rtype <name> <accepted|rejected> want <...>".
 */
static void
bottom_rtype_mutants(void)
{
	static const struct {
		const char *name;
		dtrace_diftype_t rt;
		int accept;
	} m[] = {
		{ "unchanged", { DIF_TYPE_BOTTOM, 0, 0, 0, 0 }, 1 },
		{ "bottom-marker", { DIF_TYPE_BOTTOM, (uint8_t)CTF_BOTTOM_TYPE,
		    0, 0, 0 }, 1 },
		{ "kind-none", { DIF_TYPE_NONE, 0, 0, 0, 0 }, 0 },
		{ "kind-invalid", { 7, 0, 0, 0, 0 }, 0 },
		{ "bottom-ckind", { DIF_TYPE_BOTTOM, CTF_K_STRUCT, 0, 0, 0 }, 0 },
		{ "bottom-size", { DIF_TYPE_BOTTOM, 0, 0, 0, 4096 }, 0 },
		{ "bottom-flags", { DIF_TYPE_BOTTOM, 0, DIF_TF_BYREF, 0, 0 }, 0 },
		{ "ctf-int", { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 4 }, 1 },
		{ "ctf-pointer", { DIF_TYPE_CTF, CTF_K_POINTER, 0, 0, 8 }, 1 },
		{ "ctf-byvalue-16", { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 16 }, 0 },
		{ "ctf-byvalue-4096", { DIF_TYPE_CTF, CTF_K_STRUCT, 0, 0, 4096 },
		    0 },
		{ "ctf-byvalue-3", { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 3 }, 0 },
		{ "ctf-array-byref", { DIF_TYPE_CTF, CTF_K_ARRAY, DIF_TF_BYREF, 0,
		    64 }, 1 },
		{ "ctf-byref-zero", { DIF_TYPE_CTF, CTF_K_ARRAY, DIF_TF_BYREF, 0,
		    0 }, 0 },
		{ "ctf-byuref-added", { DIF_TYPE_CTF, CTF_K_ARRAY, DIF_TF_BYUREF,
		    0, 64 }, 0 },
		{ "ctf-unknown-flag", { DIF_TYPE_CTF, CTF_K_INTEGER, 0x4, 0, 8 },
		    0 },
		{ "ctf-void", { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 0 }, 1 },
		{ "ctf-exit-int", { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 0, 4 }, 1 },
		{ "string", { DIF_TYPE_STRING, 0, DIF_TF_BYREF, 0, 256 }, 1 },
		{ "string-byvalue", { DIF_TYPE_STRING, 0, 0, 0, 256 }, 0 },
		{ "string-byuref", { DIF_TYPE_STRING, 0, DIF_TF_BYREF |
		    DIF_TF_BYUREF, 0, 256 }, 0 },
		{ "pad", { DIF_TYPE_CTF, CTF_K_INTEGER, 0, 1, 8 }, 0 },
		/* The CTF kind fits how the value is returned (registers:
		 * integer, enum, float, pointer; by reference: array, struct,
		 * union).  dtdt_ckind is a kind, never a CTF type id. */
		{ "ctf-enum", { DIF_TYPE_CTF, CTF_K_ENUM, 0, 0, 4 }, 1 },
		{ "ctf-float", { DIF_TYPE_CTF, CTF_K_FLOAT, 0, 0, 8 }, 1 },
		{ "ctf-struct-byref", { DIF_TYPE_CTF, CTF_K_STRUCT, DIF_TF_BYREF,
		    0, 36 }, 1 },
		{ "ctf-union-byref", { DIF_TYPE_CTF, CTF_K_UNION, DIF_TF_BYREF,
		    0, 8 }, 1 },
		{ "ctf-struct-byvalue", { DIF_TYPE_CTF, CTF_K_STRUCT, 0, 0, 8 },
		    0 },
		{ "ctf-type-id-as-kind", { DIF_TYPE_CTF, 0x5d, 0, 0, 8 }, 0 },
		{ "ctf-integer-byref", { DIF_TYPE_CTF, CTF_K_INTEGER,
		    DIF_TF_BYREF, 0, 64 }, 0 },
		{ "ctf-pointer-byref", { DIF_TYPE_CTF, CTF_K_POINTER,
		    DIF_TF_BYREF, 0, 8 }, 0 },
		/* A by-reference result is at most guestrefsize bytes
		 * (64 KiB by default). */
		{ "ctf-byref-at-bound", { DIF_TYPE_CTF, CTF_K_STRUCT,
		    DIF_TF_BYREF, 0, 64 * 1024 }, 1 },
		{ "ctf-byref-over-bound", { DIF_TYPE_CTF, CTF_K_STRUCT,
		    DIF_TF_BYREF, 0, 64 * 1024 + 1 }, 0 },
		{ "ctf-byuref-over-bound", { DIF_TYPE_CTF, CTF_K_ARRAY,
		    DIF_TF_BYUREF, 0, 1U << 31 }, 0 },
	};
	dif_instr_t code[] = { DIF_INSTR_RET(0) };
	dtrace_difo_t base = { 0 }, guest = { 0 };
	char target[] = "test:::bottom";
	dtrace_hdl_t *dtp;
	void *ctx;
	int err;

	dtp = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV, &err);
	if (dtp == NULL)
		return;
	ctx = dt_verictx_init(dtp);
	base.dtdo_buf = guest.dtdo_buf = code;
	base.dtdo_len = guest.dtdo_len = 1;
	base.dtdo_rtype.dtdt_kind = DIF_TYPE_BOTTOM;
	for (size_t i = 0; i < sizeof (m) / sizeof (m[0]); i++) {
		int v;

		guest.dtdo_rtype = m[i].rt;
		v = dt_prog_verify_difo(ctx, &base, &guest, target, target);
		dprintf(STDOUT_FILENO, "bottom-rtype %s %s want %s\n", m[i].name,
		    v == 0 ? "accepted" : "rejected",
		    m[i].accept ? "accepted" : "rejected");
	}
	/* The option raises the bound (and refuses nonsense). */
	{
		int ok = dtrace_setopt(dtp, "guestrefsize", "1m") == 0 &&
		    dtrace_setopt(dtp, "guestrefsize", "0") != 0 &&
		    dtrace_setopt(dtp, "guestrefsize", "lots") != 0;
		guest.dtdo_rtype = (dtrace_diftype_t){ DIF_TYPE_CTF,
		    CTF_K_STRUCT, DIF_TF_BYREF, 0, 64 * 1024 + 1 };
		ok = ok && dt_prog_verify_difo(ctx, &base, &guest, target,
		    target) == 0;
		guest.dtdo_rtype.dtdt_size = 1024 * 1024 + 1;
		ok = ok && dt_prog_verify_difo(ctx, &base, &guest, target,
		    target) != 0;
		dprintf(STDOUT_FILENO, "bottom-rtype guestrefsize-option %s "
		    "want accepted\n", ok ? "accepted" : "rejected");
	}
	dt_verictx_teardown(ctx);
	dtrace_close(dtp);
}

int
main(void)
{
	size_t i;
	int failures = 0;

	bottom_rtype_mutants();

	for (i = 0; i < sizeof (programs) / sizeof (programs[0]); i++) {
		pid_t pid;
		int status;

		pid = fork();
		if (pid == 0) {
			/* exit(), not _exit(): coverage profiles are written at exit. */
			exit(run_program((int)i));
		}
		if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
		    WEXITSTATUS(status) != 0) {
			dprintf(STDOUT_FILENO, "program %zu: child %s %d\n", i,
			    WIFSIGNALED(status) ? "signal" : "status",
			    WIFSIGNALED(status) ? WTERMSIG(status) :
			    WEXITSTATUS(status));
			failures++;
		}
	}
	dprintf(STDOUT_FILENO, "%d program(s) failed to run\n", failures);
	return (failures != 0);
}
