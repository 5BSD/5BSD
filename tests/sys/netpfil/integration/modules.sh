#
# SPDX-License-Identifier: BSD-2-Clause
#
# 5BSD seam tests: the capability plane, pf's modules and its rc.d scripts.
#
# The capability plane denies kldload(2) after boot: pf and the DTrace
# providers are preloaded by the loader (stand/defaults/loader.conf), and
# other modules are loaded through the SystemExtension broker
# (sysextctl load, rc.subr "load_kld -b", allow-list in
# usr.sbin/BSDExtension/bsdextension.ucl).  pf.ko contains pflog, pfsync
# and pflow as interface cloners; there are no separate modules for them
# and no interfaces are precreated.

. $(atf_get_srcdir)/integration.subr

# The rc.d cases run the scripts as "env _rc_conf_loaded=true var=value ...
# /etc/rc.d/<script> one<command>": _rc_conf_loaded=true stops
# load_rc_config from sourcing /etc/defaults/rc.conf and /etc/rc.conf, so
# the scripts see only the given variables and the host's configuration is
# neither read nor changed.

atf_test_case "pf_loaded"
pf_loaded_head()
{
	atf_set descr 'pf is loaded at boot and /dev/pf exists'
	atf_set require.user root
}

pf_loaded_body()
{
	atf_check -s exit:0 kldstat -q -m pf
	atf_check -s exit:0 test -c /dev/pf
	atf_check -s exit:0 -o match:'^Status: ' pfctl -si
}

atf_test_case "dummynet_loaded"
dummynet_loaded_head()
{
	atf_set descr 'dummynet is loaded at boot (loader defaults) and dnctl works'
	atf_set require.user root
}

dummynet_loaded_body()
{
	atf_check -s exit:0 kldstat -q -m dummynet
	atf_check -s exit:0 -o ignore dnctl pipe show
}

atf_test_case "dtrace_loaded"
dtrace_loaded_head()
{
	atf_set descr 'The DTrace framework and SDT provider are loaded at boot'
	atf_set require.user root
}

dtrace_loaded_body()
{
	atf_check -s exit:0 kldstat -q -m dtrace
	atf_check -s exit:0 kldstat -q -m sdt
	atf_check -s exit:0 test -c /dev/dtrace/dtrace
}

atf_test_case "no_separate_modules"
no_separate_modules_head()
{
	atf_set descr 'pflog, pfsync and pflow are not separate kernel modules'
	atf_set require.user root
}

no_separate_modules_body()
{
	for m in pflog pfsync pflow; do
		atf_check -s not-exit:0 kldstat -q -m ${m}
		atf_check -s not-exit:0 kldstat -q -n ${m}.ko
		atf_check -s not-exit:0 test -e /boot/kernel/${m}.ko
	done
}

atf_test_case "cloners_listed"
cloners_listed_head()
{
	atf_set descr 'ifconfig -C lists the pflog, pfsync and pflow cloners'
	atf_set require.user root
}

cloners_listed_body()
{
	for c in pflog pfsync pflow; do
		integ_has_cloner ${c} ||
		    atf_fail "ifconfig -C does not list ${c}: $(ifconfig -C)"
	done
}

atf_test_case "kldload_denied" "cleanup"
kldload_denied_head()
{
	atf_set descr 'A direct kldload after boot is denied by the capability plane'
	atf_set require.user root
}

kldload_denied_body()
{
	mod=
	for m in dummynet if_disc if_edsc sysvmsg; do
		if ! kldstat -q -m ${m} && ! kldstat -q -n ${m}.ko &&
		    [ -f /boot/kernel/${m}.ko ]; then
			mod=${m}
			break
		fi
	done
	[ -n "${mod}" ] ||
	    atf_skip "every candidate module is loaded or not installed"
	echo ${mod} > tried_module

	atf_check -s not-exit:0 -e not-empty kldload ${mod}
	atf_check -s not-exit:0 kldstat -q -n ${mod}.ko
}

kldload_denied_cleanup()
{
	# If the denial failed, the module stays loaded until reboot: report
	# it, do not unload shared kernel code behind the broker's back.
	if [ -f tried_module ] && kldstat -q -n $(cat tried_module).ko; then
		echo "$(cat tried_module).ko was loaded by a direct kldload" >&2
	fi
}

atf_test_case "broker_load_dummynet"
broker_load_dummynet_head()
{
	atf_set descr 'sysextctl load dummynet (the SystemExtension broker) loads dummynet'
	atf_set require.user root
}

broker_load_dummynet_body()
{
	integ_require_prog sysextctl
	if ! sysextctl status dummynet > status.out 2>&1; then
		cat status.out
		atf_skip "the SystemExtension broker is not reachable from the test environment"
	fi
	atf_check -o match:'^dummynet: allowed' cat status.out

	atf_check -s exit:0 -o match:'^dummynet: loaded' sysextctl load dummynet
	atf_check -s exit:0 kldstat -q -m dummynet
	atf_check -s exit:0 -o match:'loaded=yes' sysextctl status dummynet
	# Loading an already loaded module is success.
	atf_check -s exit:0 -o match:'^dummynet: loaded' sysextctl load dummynet
}

atf_test_case "rc_pf" "cleanup"
rc_pf_head()
{
	atf_set descr 'rc.d/pf onestart, onestatus, onecheck, onestop in a VNET jail'
	atf_set require.user root
}

rc_pf_body()
{
	pft_init
	vnet_mkjail a
	host_before=$(pfctl -si | awk '/^Status:/ { print $2 }')

	printf 'pass all label "rc_pf"\n' > pf.conf
	vars="pf_rules=${PWD}/pf.conf pf_program=/sbin/pfctl pf_flags="

	atf_check -s exit:0 -o ignore -e ignore \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pf onecheck
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pf onestart
	atf_check -o match:'^Status: Enabled' jexec a pfctl -si
	atf_check -o match:'label "rc_pf"' jexec a pfctl -sr
	atf_check -s exit:0 -o match:'^Status: Enabled' \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pf onestatus

	# reload picks up a changed file.
	printf 'pass all label "rc_pf_reloaded"\n' > pf.conf
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pf onereload
	atf_check -o match:'label "rc_pf_reloaded"' jexec a pfctl -sr

	atf_check -s exit:0 -o match:'Disabling pf' \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pf onestop
	atf_check -o match:'^Status: Disabled' jexec a pfctl -si
	atf_check -s not-exit:0 -o match:'^Status: Disabled' \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pf onestatus

	# A broken ruleset fails onecheck.
	printf 'pass from $undefined_macro\n' > bad.conf
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jexec a env _rc_conf_loaded=true pf_rules=${PWD}/bad.conf \
	    pf_program=/sbin/pfctl /etc/rc.d/pf onecheck

	host_after=$(pfctl -si | awk '/^Status:/ { print $2 }')
	[ "${host_before}" = "${host_after}" ] ||
	    atf_fail "host pf status changed from ${host_before} to ${host_after}"
}

rc_pf_cleanup()
{
	integ_cleanup
}

atf_test_case "rc_pf_fallback" "cleanup"
rc_pf_fallback_head()
{
	atf_set descr 'rc.d/pf loads the fallback rules when the ruleset is broken'
	atf_set require.user root
}

rc_pf_fallback_body()
{
	pft_init
	vnet_mkjail a

	printf 'pass from $undefined_macro\n' > bad.conf
	atf_check -s exit:0 -o ignore -e match:'Loading fallback rules' \
	    jexec a env _rc_conf_loaded=true pf_rules=${PWD}/bad.conf \
	    pf_program=/sbin/pfctl pf_fallback_rules_enable=YES \
	    pf_fallback_rules_file=${PWD}/nonexistent \
	    "pf_fallback_rules=block drop log all label fallback" \
	    /etc/rc.d/pf onestart
	atf_check -o match:'^block drop log all label "fallback"' \
	    jexec a pfctl -sr
	atf_check -o match:'^Status: Enabled' jexec a pfctl -si
}

rc_pf_fallback_cleanup()
{
	integ_cleanup
}

atf_test_case "rc_pflog" "cleanup"
rc_pflog_head()
{
	atf_set descr 'rc.d/pflog creates pflog0 and runs pflogd in a VNET jail'
	atf_set require.user root
}

rc_pflog_body()
{
	pflog_init
	integ_require_prog pflogd
	vnet_mkjail a

	atf_check -s not-exit:0 -e ignore jexec a ifconfig pflog0

	# Named instance: its own pidfile, so a host pflogd is not disturbed.
	vars="pflog_instances=integ pflog_integ_dev=pflog0"
	vars="${vars} pflog_integ_logfile=${PWD}/pflog.pcap"
	atf_check -s exit:0 -o ignore -e ignore \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pflog onestart integ
	atf_check -s exit:0 -o match:'flags=.*UP' jexec a ifconfig pflog0
	atf_check -s exit:0 -o not-empty pgrep -j a pflogd

	atf_check -s exit:0 -o ignore -e ignore \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pflog onestop integ
	n=0
	while pgrep -q -j a pflogd && [ $n -lt 50 ]; do
		sleep 0.1
		n=$((n + 1))
	done
	atf_check -s not-exit:0 pgrep -j a pflogd
	# Stopping the logger leaves the interface.
	atf_check -s exit:0 -o ignore jexec a ifconfig pflog0
}

rc_pflog_cleanup()
{
	pkill -j a pflogd 2>/dev/null
	rm -f /var/run/pflogd.integ.pid
	integ_cleanup
}

atf_test_case "rc_pfsync" "cleanup"
rc_pfsync_head()
{
	atf_set descr 'rc.d/pfsync creates and configures pfsync0 in a VNET jail'
	atf_set require.user root
}

rc_pfsync_body()
{
	pfsynct_init
	epair=$(vnet_mkepair)
	vnet_mkjail a ${epair}a
	jexec a ifconfig ${epair}a 192.0.2.1/24 up

	atf_check -s not-exit:0 -e ignore jexec a ifconfig pfsync0

	# No syncdev: the prestart check refuses to start.
	atf_check -s not-exit:0 -o ignore -e match:'pfsync_syncdev is not set' \
	    jexec a env _rc_conf_loaded=true pfsync_syncdev= \
	    /etc/rc.d/pfsync onestart

	vars="pfsync_syncdev=${epair}a pfsync_syncpeer= pfsync_ifconfig="
	atf_check -s exit:0 -o match:'Enabling pfsync' -e ignore \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pfsync onestart
	atf_check -s exit:0 -o match:'flags=.*UP' jexec a ifconfig pfsync0
	atf_check -s exit:0 -o match:"syncdev:? ${epair}a" jexec a ifconfig pfsync0

	atf_check -s exit:0 -o match:'Disabling pfsync' -e ignore \
	    jexec a env _rc_conf_loaded=true ${vars} /etc/rc.d/pfsync onestop
	atf_check -s exit:0 -o not-match:"syncdev:? ${epair}a" \
	    jexec a ifconfig pfsync0
	atf_check -s exit:0 -o not-match:'flags=.*[<,]UP[,>]' \
	    jexec a ifconfig pfsync0

	# The host vnet has no pfsync0 from the jail's script.
	atf_check -s ignore -o not-match:"syncdev:? ${epair}a" -e ignore \
	    ifconfig pfsync0
}

rc_pfsync_cleanup()
{
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "pf_loaded"
	atf_add_test_case "dummynet_loaded"
	atf_add_test_case "dtrace_loaded"
	atf_add_test_case "no_separate_modules"
	atf_add_test_case "cloners_listed"
	atf_add_test_case "kldload_denied"
	atf_add_test_case "broker_load_dummynet"
	atf_add_test_case "rc_pf"
	atf_add_test_case "rc_pf_fallback"
	atf_add_test_case "rc_pflog"
	atf_add_test_case "rc_pfsync"
}
