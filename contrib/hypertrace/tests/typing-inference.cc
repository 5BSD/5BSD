/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * HyperTrace type inference over compiled D: every valid program links and
 * every instruction's inferred type (dtdo_types[]) agrees with the
 * independent oracle in typing-oracle.h.
 *
 * Built and run by typing-inference.py, which supplies the module inventory
 * (the real kernel's CTF plus two CTF fixture objects) through a
 * kldnext()/kldstat() interposer.  Usage: typing-inference [case-name].
 */
#include "typing-oracle.h"

using namespace th;

/*
 * Names that differ from the D front end's declarations but have the same
 * size: a difference listed here would be a deliberate choice of the
 * typing pass; any other fails.
 */
static const std::set<std::tuple<std::string, std::string, std::string>>
    KNOWN_DIVERGENCES = {
	/* None: builtin variables and subroutines are typed as the D ident
	 * table declares them (arg*, harg* and rand() used to differ). */
};

static void
check_program(const char *src)
{
	dtrace_prog_t *p = compile(src);
	auto snaps = snapshot(p);
	link_ok(p);
	Oracle o;
	for (auto &s : snaps)
		o.check(s.where.c_str(), s.code, s.symtab, s.ints, s.difo,
		    s.symtab_absent);
	for (auto &f : o.failures)
		fprintf(stderr, "ORACLE: %s\n", f.c_str());
	bool bad = !o.failures.empty();
	for (auto &d : o.divergences) {
		if (!KNOWN_DIVERGENCES.count({ d.subject, d.inferred,
		    d.expected })) {
			fprintf(stderr, "DIVERGENCE: %s inferred %s, D declares %s\n",
			    d.subject.c_str(), d.inferred.c_str(),
			    d.expected.c_str());
			bad = true;
		}
	}
	CHECKF(!bad, "%s", src);
	CHECKF(o.checked > 0, "nothing checked for %s", src);
	fprintf(stderr, "checked %zu instruction types\n", o.checked);
}

#define CORPUS(name, src) \
	CASE("corpus-" name) { check_program(src); }

/* Builtin variables: every scalar builtin the D front end declares. */
CORPUS("builtins-ints", "BEGIN { trace(pid); trace(ppid); trace(tid); "
    "trace(uid); trace(gid); trace(cpu); trace(errno); trace(jid); }")
CORPUS("builtins-time", "BEGIN { trace(timestamp); trace(vtimestamp); "
    "trace(walltimestamp); }")
CORPUS("builtins-ids", "BEGIN { trace(ipl); trace(epid); trace(id); "
    "trace(stackdepth); trace(ustackdepth); trace(caller); trace(ucaller); }")
CORPUS("builtins-args", "BEGIN { trace(arg0); trace(arg1); trace(arg2); "
    "trace(arg3); trace(arg4); trace(arg5); trace(arg6); trace(arg7); "
    "trace(arg8); trace(arg9); }")
CORPUS("builtins-strings", "BEGIN { trace(execname); trace(probeprov); "
    "trace(probemod); trace(probefunc); trace(probename); trace(zonename); "
    "trace(jailname); trace(execargs); }")
CORPUS("builtins-curthread", "BEGIN { trace(curthread->td_tid); "
    "trace(curthread->td_proc->p_pid); }")
CORPUS("builtins-host", "BEGIN { trace(htimestamp); trace(hvtimestamp); "
    "trace(hwalltimestamp); trace(hpid); trace(hppid); trace(htid); "
    "trace(huid); trace(hgid); trace(herrno); trace(hjid); trace(hcpu); "
    "trace(hepid); trace(hprid); trace(hipl); trace(hstackdepth); "
    "trace(hustackdepth); trace(hcaller); trace(hucaller); }")
CORPUS("builtins-host-strings", "BEGIN { trace(hexecname); "
    "trace(hprobeprov); trace(hprobemod); trace(hprobefunc); "
    "trace(hprobename); trace(hjailname); trace(hvmname); trace(vmname); "
    "trace(hexecargs); }")
CORPUS("builtins-host-args", "BEGIN { trace(harg0 + harg1 + harg2 + harg3 "
    "+ harg4 + harg5 + harg6 + harg7 + harg8 + harg9); }")
CORPUS("builtins-host-curthread", "BEGIN { trace(hcurthread->td_tid); }")
CORPUS("builtins-regs", "BEGIN { trace(uregs[0]); trace(regs[1]); }")
/* Member access and casts. */
CORPUS("member-chain", "BEGIN { this->p = curthread->td_proc; "
    "trace(this->p->p_pid); trace(this->p->p_ucred->cr_uid); }")
CORPUS("member-local-struct-ptr", "BEGIN { this->t = curthread; "
    "trace(this->t->td_tid); }")
CORPUS("cast-kernel-struct", "BEGIN { trace(((struct proc *)arg0)->p_pid); }")
CORPUS("cast-userland", "BEGIN { this->x = (userland uint32_t *)arg0; "
    "trace((uintptr_t)this->x); }")
CORPUS("cast-int-widths", "BEGIN { this->a = (int8_t)arg0; "
    "this->b = (uint16_t)arg1; this->c = (int32_t)arg2; "
    "this->d = (uint64_t)arg3; trace(this->a + this->b + this->c + this->d); }")
CORPUS("member-module-struct", "BEGIN { this->q = "
    "(struct typingfix`tf_pair *)arg0; trace(this->q->b); }")
/* Variables of every scope. */
CORPUS("var-global-int", "BEGIN { g = timestamp; trace(g + 1); }")
CORPUS("var-thread-ptr", "BEGIN { self->t = curthread; "
    "trace(self->t->td_tid); }")
CORPUS("var-global-ptr", "BEGIN { gp = curthread->td_proc; "
    "trace(gp->p_pid); }")
CORPUS("var-string", "BEGIN { s = execname; this->s = s; trace(this->s); }")
CORPUS("var-assoc", "BEGIN { a[pid] = curthread; trace(a[pid]->td_tid); }")
CORPUS("var-assoc-thread", "BEGIN { self->a[tid, execname] = timestamp; "
    "trace(self->a[tid, execname]); }")
/* Subroutines. */
CORPUS("subr-strings", "BEGIN { trace(strlen(execname)); "
    "trace(strjoin(execname, \"x\")); trace(substr(execname, 1)); "
    "trace(substr(execname, 1, 2)); trace(index(execname, \"a\")); "
    "trace(rindex(execname, \"a\", 2)); trace(strchr(execname, 'a')); "
    "trace(strrchr(execname, 'a')); trace(strstr(execname, \"a\")); "
    "trace(strtok(execname, \"/\")); }")
CORPUS("subr-paths", "BEGIN { trace(basename(execname)); "
    "trace(dirname(execname)); trace(cleanpath(execname)); "
    "trace(toupper(execname)); trace(tolower(execname)); }")
CORPUS("subr-conv", "BEGIN { trace(lltostr(timestamp)); "
    "trace(lltostr(timestamp, 16)); trace(strtoll(\"12\")); "
    "trace(strtoll(\"12\", 8)); }")
CORPUS("subr-bytes", "BEGIN { trace(htons(1)); trace(htonl(1)); "
    "trace(htonll(1)); trace(ntohs(1)); trace(ntohl(1)); trace(ntohll(1)); }")
CORPUS("subr-misc", "BEGIN { trace(rand()); trace(random()); "
    "trace(progenyof(1)); trace(speculation()); }")
CORPUS("subr-copy", "BEGIN { trace(*(int *)copyin(arg0, 4)); "
    "trace(copyinstr(arg0)); trace(copyinstr(arg0, 8)); }")
CORPUS("subr-alloca", "BEGIN { this->b = (char *)alloca(8); "
    "copyinto(arg0, 4, this->b); bcopy(execname, this->b, 2); "
    "trace(this->b[0]); }")
CORPUS("subr-locks", "BEGIN { trace(mutex_owned((struct mtx *)arg0)); "
    "trace(mutex_owner((struct mtx *)arg0)); "
    "trace(mutex_type_adaptive((struct mtx *)arg0)); "
    "trace(mutex_type_spin((struct mtx *)arg0)); }")
CORPUS("subr-rwlocks", "BEGIN { trace(rw_read_held((struct rwlock *)arg0)); "
    "trace(rw_write_held((struct rwlock *)arg0)); "
    "trace(rw_iswriter((struct rwlock *)arg0)); }")
CORPUS("subr-sxlocks", "BEGIN { trace(sx_shared_held((struct sx *)arg0)); "
    "trace(sx_exclusive_held((struct sx *)arg0)); "
    "trace(sx_isexclusive((struct sx *)arg0)); }")
CORPUS("subr-inet", "BEGIN { trace(inet_ntoa((in_addr_t *)arg0)); "
    "trace(inet_ntoa6((struct in6_addr *)arg0)); "
    "trace(inet_ntop(2, (void *)arg0)); }")
CORPUS("subr-memref", "BEGIN { trace(memref((void *)arg0, 8)); }")
CORPUS("subr-json", "BEGIN { trace(json(\"{\\\"a\\\":1}\", \"a\")); }")
CORPUS("subr-copyout", "BEGIN { copyout((void *)arg0, arg1, 4); "
    "copyoutstr(execname, arg1, 8); }")
/* Arithmetic, comparisons and control flow. */
CORPUS("arith-ops", "BEGIN { x = timestamp; trace((x & 0xff) | (x ^ 3)); "
    "trace(x << 2 >> 1); trace(x * 3 / 2 % 5 - 1); trace(-x); trace(~x); }")
CORPUS("arith-signed", "BEGIN { this->v = (int)arg0; trace(this->v / 3); "
    "trace(this->v % 3); trace(this->v >> 1); }")
CORPUS("cond-ternary", "BEGIN { trace(pid > 1 ? pid : ppid); }")
CORPUS("cond-ternary-string", "BEGIN { trace(pid > 1 ? execname : \"x\"); }")
CORPUS("cond-if", "BEGIN { if (pid > 1) { trace(1); } else { trace(2); } }")
CORPUS("cond-predicate", "BEGIN /curthread->td_tid != 0/ { trace(1); }")
CORPUS("cmp-strings", "BEGIN { trace(execname == \"init\"); "
    "trace(execname < \"z\"); }")
/* Aggregations and actions with typed keys/values. */
CORPUS("agg-keys", "BEGIN { @c[curthread->td_tid, execname] = count(); "
    "@s[pid] = sum(curthread->td_tid); @q = quantize(timestamp); }")
CORPUS("act-printf", "BEGIN { printf(\"%d %s\\n\", curthread->td_tid, "
    "execname); }")
CORPUS("act-tracemem", "BEGIN { tracemem(curthread, 16); }")
CORPUS("act-exit", "BEGIN { exit(curthread->td_tid != 0); }")

/* Regressions: a store and a load of the same variable in one DIFO
 * (strcmp() of two absent symbols crashed the linker), and index() with a
 * CTF haystack and a string needle (the needle was checked as a CTF
 * type). */
CORPUS("regress-store-then-load-local",
    "BEGIN { trace((this->x = timestamp) + this->x); }")
CORPUS("regress-store-then-load-local-ptr",
    "BEGIN { trace((this->p = curthread) == this->p); }")
CORPUS("regress-store-then-load-thread",
    "BEGIN { trace((self->x = timestamp) + self->x); }")
CORPUS("regress-index-ctf-haystack", "BEGIN { trace(index((char *)arg0, "
    "\"a\")); trace(rindex((char *)arg0, (char *)arg1)); }")

int
main(int argc, char **argv)
{
	int err;
	handle() = dtrace_open(DTRACE_VERSION, DTRACE_O_NODEV, &err);
	if (handle() == nullptr) {
		fprintf(stderr, "dtrace_open: %s\n", dtrace_errmsg(nullptr, err));
		return (3);
	}
	return (run_all(argc, argv));
}
