/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Shared framework for the HyperTrace type-inference suites
 * (typing-inference.py and its C++ harnesses).
 *
 * Every case runs in its own forked child.  A case either completes
 * (PASS), fails a CHECK (exit status 2), or aborts on an assertion.  A
 * PROGERR_CASE must complete after a program error (dt_set_progerr()) was
 * recorded with its diagnostic, and every type inference or link that
 * recorded one must have returned failure (libdtrace no longer ends the
 * process on a program error).  The parent captures the child's stderr so
 * that cases expecting a diagnostic can match it.  Children use exit(),
 * never _exit(), so their coverage profiles are written.
 */
#ifndef _TYPING_HARNESS_H_
#define _TYPING_HARNESS_H_

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <execinfo.h>
#include <exception>
#include <functional>
#include <set>
#include <string>
#include <vector>

typedef enum { B_FALSE, B_TRUE } boolean_t;
typedef int64_t hrtime_t;

#include <dt_impl.h>
#include <dt_program.h>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_inttab.h>
#include <dt_strtab.h>
#include <dt_typefile.hh>
#include <dt_typing_helpers.hh>
#include <dt_linker_subr.hh>
/* Expose private members of the classes under test.  Every library header
 * is included first so that the macro cannot change their definitions. */
#define private public
#include <dt_hypertrace_linker.hh>
#include <dt_typing.hh>
#include <dt_typing_var.hh>
#undef private

extern "C" void dt_dis(const dtrace_difo_t *, FILE *);

namespace th {

enum class Expect { Pass, ProgErr, Abort, Fail };

/*
 * Set by the helpers (link(), Unit) in the child: a program error was
 * recorded, or one was recorded by a call that nevertheless succeeded.
 */
inline int progerr_recorded = 0;
inline int progerr_unreturned = 0;

inline void
note_progerr(bool recorded, bool returned)
{
	if (recorded) {
		progerr_recorded = 1;
		if (!returned)
			progerr_unreturned = 1;
	}
}

struct Case {
	std::string name;
	Expect expect;
	std::string text; /* expected stderr substring (ProgErr/Fail) */
	std::function<void()> body;
};

inline std::vector<Case> &
registry()
{
	static std::vector<Case> r;
	return (r);
}

struct Reg {
	Reg(const char *name, Expect e, const char *text, std::function<void()> f)
	{
		registry().push_back({ name, e, text ? text : "", f });
	}
};

#define TH_CAT2(a, b) a##b
#define TH_CAT(a, b) TH_CAT2(a, b)
/* A case that must complete and print PASS. */
#define CASE(name) \
	static void TH_CAT(case_, __LINE__)(); \
	static th::Reg TH_CAT(reg_, __LINE__)(name, th::Expect::Pass, nullptr, \
	    TH_CAT(case_, __LINE__)); \
	static void TH_CAT(case_, __LINE__)()
/* A case that must stop at a failed assert() whose text includes this. */
#define ABORT_CASE(name, text) \
	static void TH_CAT(case_, __LINE__)(); \
	static th::Reg TH_CAT(reg_, __LINE__)(name, th::Expect::Abort, text, \
	    TH_CAT(case_, __LINE__)); \
	static void TH_CAT(case_, __LINE__)()
/* A case that must record and return a program error with this text. */
#define PROGERR_CASE(name, text) \
	static void TH_CAT(case_, __LINE__)(); \
	static th::Reg TH_CAT(reg_, __LINE__)(name, th::Expect::ProgErr, text, \
	    TH_CAT(case_, __LINE__)); \
	static void TH_CAT(case_, __LINE__)()

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, \
			    __LINE__, #cond); \
			exit(2); \
		} \
	} while (0)
#define CHECKF(cond, ...) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "CHECK failed %s:%d: %s: ", __FILE__, \
			    __LINE__, #cond); \
			fprintf(stderr, __VA_ARGS__); \
			fprintf(stderr, "\n"); \
			exit(2); \
		} \
	} while (0)

/* The handle opened by the parent before forking (shared CTF state). */
inline dtrace_hdl_t *&
handle()
{
	static dtrace_hdl_t *h;
	return (h);
}

/* Extra compiler flags for every compile (e.g. DTRACE_C_NOLIBS when the
 * kernel's types are deliberately missing). */
inline uint_t &
extra_cflags()
{
	static uint_t f;
	return (f);
}

inline dtrace_prog_t *
compile(const char *src, uint_t cflags = DTRACE_C_ZDEFS)
{
	dtrace_hdl_t *h = handle();
	cflags |= extra_cflags();
	dtrace_prog_t *p = dtrace_program_strcompile(h, src,
	    DTRACE_PROBESPEC_NAME, cflags, 0, NULL);
	CHECKF(p != nullptr, "compile '%s': %s", src,
	    dtrace_errmsg(h, dtrace_errno(h)));
	return (p);
}

/* Visit every DIFO (predicate first, then actions) of a program. */
inline void
for_each_difo(dtrace_prog_t *p,
    const std::function<void(dtrace_stmtdesc_t *, dtrace_actdesc_t *,
	dtrace_difo_t *)> &fn)
{
	for (dt_stmt_t *s = (dt_stmt_t *)dt_list_next(&p->dp_stmts); s;
	     s = (dt_stmt_t *)dt_list_next(s)) {
		dtrace_stmtdesc_t *sd = s->ds_desc;
		if (sd->dtsd_ecbdesc->dted_pred.dtpdd_difo != nullptr)
			fn(sd, nullptr, sd->dtsd_ecbdesc->dted_pred.dtpdd_difo);
		for (dtrace_actdesc_t *a = sd->dtsd_action; a != nullptr;
		     a = a->dtad_next) {
			if (a->dtad_difo != nullptr)
				fn(sd, a, a->dtad_difo);
			if (a == sd->dtsd_action_last)
				break;
		}
	}
}

inline dtrace_difo_t *
first_action_difo(dtrace_prog_t *p)
{
	dt_stmt_t *s = (dt_stmt_t *)dt_list_next(&p->dp_stmts);
	CHECK(s != nullptr && s->ds_desc->dtsd_action != nullptr);
	return (s->ds_desc->dtsd_action->dtad_difo);
}

inline int
link(dtrace_prog_t *p, std::string *msg = nullptr)
{
	char buf[HYPERTRACE_ERRMSGLEN] = { 0 };
	int r = hypertrace_link(handle(), p, buf);
	if (msg != nullptr)
		*msg = buf;
	th::note_progerr(p->dp_haserror != 0, r != 0);
	return (r);
}

inline void
link_ok(dtrace_prog_t *p)
{
	std::string msg;
	int r = link(p, &msg);
	CHECKF(r == 0 && msg.empty(), "link returned %d: %s", r, msg.c_str());
}

/* Replace a DIFO's code and tables by hand-assembled ones. */
struct Difo {
	std::vector<dif_instr_t> code;
	std::vector<uint64_t> ints;
	std::string strs;
	std::string syms;
	std::vector<dtrace_difv_t> vars;
	bool symtab = true; /* typing runs only for DIFOs with a symtab */

	/* Intern a string into the symbol table and return its offset. */
	uint_t
	sym(const char *s)
	{
		uint_t off = (uint_t)syms.size();
		syms.append(s);
		syms.push_back('\0');
		return (off);
	}
	uint_t
	str(const char *s)
	{
		uint_t off = (uint_t)strs.size();
		strs.append(s);
		strs.push_back('\0');
		return (off);
	}
	uint_t
	integer(uint64_t v)
	{
		ints.push_back(v);
		return ((uint_t)ints.size() - 1);
	}
	void
	var(const char *name, uint_t id, uint8_t kind, uint8_t scope,
	    uint8_t dkind = DIF_TYPE_BOTTOM, uint32_t size = 0)
	{
		dtrace_difv_t v;
		memset(&v, 0, sizeof(v));
		v.dtdv_name = str(name);
		v.dtdv_id = id;
		v.dtdv_kind = kind;
		v.dtdv_scope = scope;
		v.dtdv_type.dtdt_kind = dkind;
		v.dtdv_type.dtdt_size = size;
		v.dtdv_ctfid = CTF_ERR;
		vars.push_back(v);
	}
	void
	install(dtrace_difo_t *d) const
	{
		d->dtdo_len = (uint_t)code.size();
		d->dtdo_buf = (dif_instr_t *)calloc(code.size() + 1,
		    sizeof(dif_instr_t));
		memcpy(d->dtdo_buf, code.data(), code.size() * sizeof(dif_instr_t));
		d->dtdo_intlen = (uint_t)ints.size();
		d->dtdo_inttab = ints.empty() ? nullptr :
		    (uint64_t *)calloc(ints.size(), sizeof(uint64_t));
		if (!ints.empty())
			memcpy(d->dtdo_inttab, ints.data(),
			    ints.size() * sizeof(uint64_t));
		d->dtdo_strlen = (uint_t)strs.size();
		d->dtdo_strtab = strs.empty() ? nullptr : (char *)calloc(1,
		    strs.size());
		if (!strs.empty())
			memcpy(d->dtdo_strtab, strs.data(), strs.size());
		d->dtdo_varlen = (uint_t)vars.size();
		d->dtdo_vartab = vars.empty() ? nullptr :
		    (dtrace_difv_t *)calloc(vars.size(), sizeof(dtrace_difv_t));
		if (!vars.empty())
			memcpy(d->dtdo_vartab, vars.data(),
			    vars.size() * sizeof(dtrace_difv_t));
		if (symtab) {
			std::string s = syms.empty() ? std::string(1, '\0') : syms;
			d->dtdo_symlen = s.size();
			d->dtdo_symtab = (char *)calloc(1, s.size());
			memcpy(d->dtdo_symtab, s.data(), s.size());
		} else {
			d->dtdo_symlen = 0;
			d->dtdo_symtab = nullptr;
		}
		d->dtdo_types = nullptr;
		d->dtdo_inthash = nullptr;
	}
};

/* A program whose single action DIFO is replaced by `d'. */
inline dtrace_prog_t *
program_with(const Difo &d, const char *src = "BEGIN { trace(1); }")
{
	dtrace_prog_t *p = compile(src);
	d.install(first_action_difo(p));
	return (p);
}

inline int
run_all(int argc, char **argv)
{
	int failures = 0, ran = 0;
	std::set<std::string> only(argv + 1, argv + argc);
	/* The logging pass: every inference and link step also logs. */
	if (getenv("TYPING_LOG") != nullptr) {
		log_hypertrace_typing = 1;
		log_hypertrace_linker = 1;
	}
	for (auto &c : registry()) {
		if (!only.empty() && !only.count(c.name))
			continue;
		ran++;
		int pipefd[2];
		if (pipe(pipefd) != 0)
			return (3);
		fflush(stdout);
		fflush(stderr);
		pid_t pid = fork();
		if (pid == 0) {
			/* A runaway case must not exhaust the host. */
			struct rlimit rl = { 3UL << 30, 3UL << 30 };
			setrlimit(RLIMIT_AS, &rl);
			struct rlimit nocore = { 0, 0 };
			setrlimit(RLIMIT_CORE, &nocore);
			alarm(120);
			std::set_terminate([] {
				void *bt[64];
				int n = backtrace(bt, 64);
				fprintf(stderr, "TERMINATE (uncaught exception)\n");
				backtrace_symbols_fd(bt, n, STDERR_FILENO);
				abort();
			});
			close(pipefd[0]);
			dup2(pipefd[1], STDERR_FILENO);
			close(pipefd[1]);
			c.body();
			if (progerr_recorded)
				fprintf(stderr, "PROGERR-RECORDED\n");
			if (progerr_unreturned)
				fprintf(stderr, "PROGERR-NOT-RETURNED\n");
			fprintf(stderr, "CASE-COMPLETED\n");
			exit(0);
		}
		close(pipefd[1]);
		std::string err;
		char buf[4096];
		ssize_t n;
		while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
			err.append(buf, (size_t)n);
		close(pipefd[0]);
		int status = 0;
		waitpid(pid, &status, 0);
		bool ok = false;
		const char *why = "";
		bool completed = err.find("CASE-COMPLETED") != std::string::npos;
		bool unreturned = err.find("PROGERR-NOT-RETURNED") !=
		    std::string::npos;
		switch (c.expect) {
		case Expect::Pass:
			ok = WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
			    completed && !unreturned;
			why = "expected the case to complete (with every program "
			    "error returned)";
			break;
		case Expect::ProgErr:
			ok = WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
			    completed && !unreturned &&
			    err.find("PROGERR-RECORDED") != std::string::npos &&
			    err.find(c.text) != std::string::npos;
			why = "expected a returned program error with text";
			break;
		case Expect::Abort:
			ok = WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT &&
			    err.find("Assertion failed") != std::string::npos &&
			    err.find(c.text) != std::string::npos;
			why = "expected an assertion failure with text";
			break;
		case Expect::Fail:
			ok = false;
			break;
		}
		std::string status_s = WIFEXITED(status) ?
		    "exit " + std::to_string(WEXITSTATUS(status)) :
		    WIFSIGNALED(status) ?
		    "signal " + std::to_string(WTERMSIG(status)) : "?";
		if (ok) {
			printf("PASS: %s\n", c.name.c_str());
		} else {
			failures++;
			printf("FAIL: %s (%s; %s '%s')\n", c.name.c_str(),
			    status_s.c_str(), why, c.text.c_str());
			/* Keep the diagnostic short but useful. */
			printf("----- stderr of %s -----\n%s\n-----\n",
			    c.name.c_str(), err.substr(0, 6000).c_str());
		}
	}
	printf("SUMMARY: %d case(s), %d failure(s)\n", ran, failures);
	return (failures != 0 || ran == 0);
}

} // namespace th

#endif
