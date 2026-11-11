# SPDX-License-Identifier: BSD-2-Clause
#
# ipcs(1) as an unattached process sees System V IPC today (dq-boundary
# design, part b0, section 6.1 item 18; oracle of T13).  ipcs -a reads
# the three listing sysctls.  The slice that gives each queue its own
# System V namespace (b6b) filters those listings for attached callers
# and must not start asking for PRIV_IPC_ADMIN on behalf of anyone: the
# number of priv_check() calls for PRIV_IPC_ADMIN (172) made during an
# unattached ipcs -a is zero, as root and as an unprivileged uid.
#
# The count comes from the priv:kernel:priv_check:priv-ok and priv-err
# SDT probes.  The capability plane refuses a late kldload, so dtrace's
# modules must be preloaded (LOADER_EXTRA='dtraceall_load="YES"' of
# tools/build/fuchsia/vm-provider.sh).  A pin does not skip.

PRIV_IPC_ADMIN=172

# count_priv UID: run ipcs -a as UID under dtrace; leave ipcs.out, and the
# probe firings for PRIV_IPC_ADMIN and for every privilege in fired.out.
count_priv()
{
	# dtrace -c splits its command at blanks and knows no quoting.
	printf 'ipcs -a > %s/ipcs.out 2>&1\necho $? > %s/ipcs.rc\n' \
	    "$2" "$2" > "$2/run.sh"
	chmod 644 "$2/run.sh"
	dtrace -q -x evaltime=exec \
	    -n 'priv:kernel:priv_check:priv-ok,priv:kernel:priv_check:priv-err
	        /pid == $target || progenyof($target)/
	        { @all = count(); }' \
	    -n "priv:kernel:priv_check:priv-ok,priv:kernel:priv_check:priv-err
	        /(pid == \$target || progenyof(\$target)) && arg0 == $PRIV_IPC_ADMIN/
	        { @adm = count(); }" \
	    -n 'END { printa("all %@d\n", @all); printa("ipc_admin %@d\n", @adm); }' \
	    -c "$(atf_get_srcdir)/procnet_boundary_helper as $1 $1 /bin/sh $2/run.sh" \
	    > fired.out 2> dtrace.err
}

check_ipcs()
{
	uid=$1
	dir=/tmp/procnet.ipcs
	rm -rf $dir
	mkdir -m 1777 $dir || atf_fail "mkdir $dir"
	chmod 1777 $dir

	command -v dtrace >/dev/null || atf_fail "dtrace(1) is needed"
	dtrace -l -n priv:kernel:priv_check:priv-ok 2>/dev/null |
	    grep -q priv-ok ||
	    atf_fail "the priv provider is not there (preload dtraceall)"

	# An object of each family for the listing to show.
	"$(atf_get_srcdir)/procnet_boundary_helper" ipcmk > ids ||
	    atf_fail "could not make the System V objects"
	read shmid semid msqid < ids

	count_priv $uid $dir || {
		cat dtrace.err
		atf_fail "dtrace failed"
	}
	cat fired.out
	cat $dir/ipcs.out
	atf_check_equal 0 "$(cat $dir/ipcs.rc)"
	# The control: the probes do fire for this process (its setuid(2),
	# for one), so a zero below is a measurement.
	all=$(awk '$1 == "all" {print $2}' fired.out)
	[ "${all:-0}" -gt 0 ] ||
	    atf_fail "no priv_check at all was seen: the count is not a measurement"
	# No aggregation key is printed when nothing was counted.
	atf_check_equal "" "$(awk '$1 == "ipc_admin" {print $2}' fired.out)"

	# The listing has the three headers and the three objects.
	atf_check -s exit:0 -o ignore grep -q "^Message Queues:" $dir/ipcs.out
	atf_check -s exit:0 -o ignore grep -q "^Shared Memory:" $dir/ipcs.out
	atf_check -s exit:0 -o ignore grep -q "^Semaphores:" $dir/ipcs.out
	atf_check -s exit:0 -o ignore grep -Eq "^q +$msqid " $dir/ipcs.out
	atf_check -s exit:0 -o ignore grep -Eq "^m +$shmid " $dir/ipcs.out
	atf_check -s exit:0 -o ignore grep -Eq "^s +$semid " $dir/ipcs.out
}

remove_ipcs()
{
	if [ -f ids ]; then
		read shmid semid msqid < ids
		ipcrm -m $shmid -s $semid -q $msqid 2>/dev/null
	fi
	rm -rf /tmp/procnet.ipcs
}

atf_test_case ipcs_root cleanup
ipcs_root_head()
{
	atf_set "descr" "ipcs -a as root: the listing, and no PRIV_IPC_ADMIN check"
	atf_set "require.user" "root"
}
ipcs_root_body()
{
	check_ipcs 0
}
ipcs_root_cleanup()
{
	remove_ipcs
}

atf_test_case ipcs_unprivileged cleanup
ipcs_unprivileged_head()
{
	atf_set "descr" "ipcs -a as an unprivileged uid: the listing, and no PRIV_IPC_ADMIN check"
	atf_set "require.user" "root"
}
ipcs_unprivileged_body()
{
	check_ipcs 4242
}
ipcs_unprivileged_cleanup()
{
	remove_ipcs
}

atf_init_test_cases()
{
	atf_add_test_case ipcs_root
	atf_add_test_case ipcs_unprivileged
}
