# SPDX-License-Identifier: BSD-2-Clause
#
# The new Linuxulator syscalls are visible to every tracing tool: truss
# (typed decoders), ktrace/kdump (names), the DTrace syscall::linux provider
# (regenerated systrace args) and the linuxulator SDT probes on the
# semantic events (seal recorded/denied, futex_waitv woken, splice bytes,
# signalfd create/notify/read, pidfd create/exit).

build_tracee()
{
	if [ -x "$(atf_get_srcdir)/linux_tracee" ]; then
		cp "$(atf_get_srcdir)/linux_tracee" .
	else
		atf_check -s exit:0 -o empty -e empty clang \
		    --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
		    -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror \
		    -I"$(atf_get_srcdir)" -o linux_tracee \
		    "$(atf_get_srcdir)/linux_tracee.c"
	fi
	atf_check -s exit:0 ./linux_tracee 1
}

atf_test_case truss
truss_head()
{
	atf_set "descr" "truss decodes the new Linux syscalls by name with typed args"
	atf_set "require.arch" "amd64"
	atf_set "require.kmods" "linux64"
	atf_set "require.progs" "truss"
	atf_set "require.user" "root"
}
truss_body()
{
	build_tracee
	truss -o truss.out ./linux_tracee 3 || atf_fail "tracee under truss"
	for name in linux_pidfd_open linux_futex_waitv linux_signalfd4 \
	    linux_mseal linux_munmap linux_splice linux_pipe2; do
		c=$(grep -c "^${name}(" truss.out)
		[ "$c" -ge 3 ] || { cat truss.out >&2; atf_fail "$name seen $c times, want >=3"; }
	done
	# typed args: mseal(addr,len,flags) shows a size and 0 flags, refused munmap EPERM
	grep -q "^linux_mseal(0x[0-9a-f]*,4096,0x0)" truss.out || { cat truss.out >&2; atf_fail "mseal args not typed"; }
	grep -q "^linux_munmap(0x[0-9a-f]*,4096).*ERR#-1 'Operation not permitted'" truss.out || { cat truss.out >&2; atf_fail "sealed munmap EPERM not shown"; }
	grep -q "^linux_futex_waitv(0x[0-9a-f]*,1,0,0x0,0).*ERR#-11" truss.out || { cat truss.out >&2; atf_fail "futex_waitv args"; }
	grep -qE "^linux_splice.*= 6( |\\()" truss.out || { cat truss.out >&2; atf_fail "splice return"; }
	if grep -q "UNKNOWN" truss.out; then cat truss.out >&2; atf_fail "truss has UNKNOWN syscalls"; fi
}

atf_test_case kdump
kdump_head()
{
	atf_set "descr" "ktrace/kdump name the new Linux syscalls"
	atf_set "require.arch" "amd64"
	atf_set "require.kmods" "linux64"
	atf_set "require.progs" "ktrace kdump"
	atf_set "require.user" "root"
}
kdump_body()
{
	build_tracee
	atf_check -s exit:0 ktrace -f k.out -t c ./linux_tracee 2
	kdump -f k.out > kdump.out
	for name in linux_pidfd_open linux_futex_waitv linux_signalfd4 \
	    linux_mseal linux_munmap linux_splice; do
		c=$(grep -c "CALL  *${name}(" kdump.out)
		[ "$c" -ge 2 ] || { grep -c CALL kdump.out >&2; atf_fail "kdump: $name seen $c, want >=2"; }
	done
	if grep -q "unknown" kdump.out; then grep unknown kdump.out | head >&2; atf_fail "kdump has unknown syscalls"; fi
}

# dtrace -c cannot take control of a static Linux binary (libproc waits for
# an rtld breakpoint), and a backgrounded dtrace is not reliably stopped by
# SIGINT here, so the script terminates itself: a tick probe calls exit(0)
# after the tracee has run.  Output lands in $1.
run_dtrace()
{
	local out=$1 script=$2 count=$3
	dtrace -q -n "$script tick-12s { exit(0); }" -o "$out" 2>dt.err &
	dtpid=$!
	sleep 3			# probes enabled well within this
	./linux_tracee $count || atf_fail "tracee failed beside dtrace"
	i=0; while kill -0 $dtpid 2>/dev/null && [ $i -lt 40 ]; do sleep 1; i=$((i + 1)); done
	if kill -0 $dtpid 2>/dev/null; then
		kill -9 $dtpid; cat dt.err >&2; atf_fail "dtrace did not exit on its tick"
	fi
	cat dt.err >&2
	cat "$out" >&2
}

dtrace_ready()
{
	kldstat -q -m dtraceall || kldload dtraceall || atf_skip "no dtrace modules"
	kldstat -q -m systrace_linux || kldload systrace_linux || atf_skip "no systrace_linux"
	dtrace -l -n 'syscall:linux:linux_mseal:entry' >/dev/null 2>&1 || atf_skip "syscall:linux provider unavailable"
}

atf_test_case dtrace_syscall
dtrace_syscall_head()
{
	atf_set "descr" "DTrace syscall::linux provider fires with args for the new syscalls"
	atf_set "require.arch" "amd64"
	atf_set "require.kmods" "linux64"
	atf_set "require.progs" "dtrace"
	atf_set "require.user" "root"
	atf_set "timeout" "180"
}
dtrace_syscall_body()
{
	build_tracee
	dtrace_ready
	for probe in linux_pidfd_open linux_futex_waitv linux_signalfd4 linux_mseal linux_splice; do
		dtrace -l -n "syscall:linux:${probe}:entry" | grep -q "$probe" || atf_fail "no entry probe for $probe"
		dtrace -l -n "syscall:linux:${probe}:return" | grep -q "$probe" || atf_fail "no return probe for $probe"
	done
	# count entries and check arg1 of mseal is the page length, return of the
	# refused munmap is EPERM (errno 1 in arg1 of return on FreeBSD systrace).
	run_dtrace dt.out '
	    syscall:linux:linux_mseal:entry /execname == "linux_tracee"/ { @mseal = count(); @len = sum(arg1); }
	    syscall:linux:linux_munmap:return /execname == "linux_tracee" && errno == EPERM/ { @denied = count(); }
	    syscall:linux:linux_futex_waitv:entry /execname == "linux_tracee"/ { @waitv = sum(arg1); }
	    syscall:linux:linux_splice:return /execname == "linux_tracee"/ { @spliced = sum(arg0); }
	    END { printa("mseal=%@d\n", @mseal); printa("len=%@d\n", @len);
		  printa("denied=%@d\n", @denied); printa("waitv=%@d\n", @waitv);
		  printa("spliced=%@d\n", @spliced); }' 4
	grep -q "^mseal=4$" dt.out || atf_fail "mseal entry count"
	grep -q "^len=16384$" dt.out || atf_fail "mseal arg1 (len) sum"
	grep -q "^denied=4$" dt.out || atf_fail "sealed munmap EPERM returns"
	grep -q "^waitv=4$" dt.out || atf_fail "futex_waitv nr_futexes arg sum"
	grep -q "^spliced=24$" dt.out || atf_fail "splice return sum"
}

atf_test_case dtrace_sdt
dtrace_sdt_head()
{
	atf_set "descr" "linuxulator SDT probes fire on the semantic events of the new syscalls"
	atf_set "require.arch" "amd64"
	atf_set "require.kmods" "linux64"
	atf_set "require.progs" "dtrace"
	atf_set "require.user" "root"
	atf_set "timeout" "180"
}
dtrace_sdt_body()
{
	build_tracee
	dtrace_ready
	for p in mmap:linux_mseal_common:sealed mmap:linux_range_sealed:denied \
	    futex:linux_futex_waitv:wait signalfd:linux_signalfd_common:create \
	    signalfd:linux_signalfd_signal:notify signalfd:linux_signalfd_read:dequeued \
	    pidfd:linux_pidfd_create:create pidfd:linux_pidfd_proc_exit:exit \
	    file:linux_splice:moved; do
		dtrace -l -n "linuxulator:$p" | grep -q "${p##*:}" || atf_fail "SDT probe linuxulator:$p not registered"
	done
	run_dtrace sdt.out '
	    linuxulator:mmap:linux_mseal_common:sealed /execname == "linux_tracee"/ { @sealed = count(); @slen = sum(arg1); }
	    linuxulator:mmap:linux_range_sealed:denied /execname == "linux_tracee"/ { @denied = count(); }
	    linuxulator:futex:linux_futex_waitv:wait /execname == "linux_tracee"/ { @wait = sum(arg0); }
	    linuxulator:signalfd:linux_signalfd_common:create /execname == "linux_tracee"/ { @sfd = count(); }
	    linuxulator:pidfd:linux_pidfd_create:create /execname == "linux_tracee" && arg0 == pid/ { @pfd = count(); }
	    linuxulator:file:linux_splice:moved /execname == "linux_tracee"/ { @moved = sum(arg2); }
	    END { printa("sealed=%@d\n", @sealed); printa("slen=%@d\n", @slen);
		  printa("denied=%@d\n", @denied); printa("wait=%@d\n", @wait);
		  printa("sfd=%@d\n", @sfd); printa("pfd=%@d\n", @pfd);
		  printa("moved=%@d\n", @moved); }' 5
	grep -q "^sealed=5$" sdt.out || atf_fail "sealed probe count"
	grep -q "^slen=20480$" sdt.out || atf_fail "sealed probe len arg"
	grep -q "^denied=5$" sdt.out || atf_fail "denied probe count"
	grep -q "^wait=5$" sdt.out || atf_fail "futex_waitv wait probe nr arg"
	grep -q "^sfd=5$" sdt.out || atf_fail "signalfd create probe"
	grep -q "^pfd=5$" sdt.out || atf_fail "pidfd create probe (pid arg == target)"
	grep -q "^moved=30$" sdt.out || atf_fail "splice moved probe bytes"
}

atf_init_test_cases()
{
	atf_add_test_case truss
	atf_add_test_case kdump
	atf_add_test_case dtrace_syscall
	atf_add_test_case dtrace_sdt
}
