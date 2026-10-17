#
# SPDX-License-Identifier: BSD-2-Clause
#
# 5BSD seam tests: pf's cloned interfaces in VNET jails.
#
# pflog(4), pfsync(4) and pflow(4) are interface cloners in pf.ko.  Unlike
# FreeBSD pf, no interface is precreated: each VNET creates the interfaces
# it needs, they live in that VNET only, and they are destroyed with it.
# pfsync has a single unit, pfsync0.

. $(atf_get_srcdir)/integration.subr

cloners_init()
{
	pft_init
	for c in pflog pfsync pflow; do
		integ_has_cloner ${c} ||
		    atf_skip "ifconfig -C does not list ${c}"
	done
}

# unit_of type: the unit the create/destroy cases use for a cloner.
unit_of()
{
	case $1 in
	pfsync)	echo 0 ;;
	*)	echo 42 ;;
	esac
}

atf_test_case "absent_until_created" "cleanup"
absent_until_created_head()
{
	atf_set descr 'A new VNET has no pflog, pfsync or pflow interface'
	atf_set require.user root
}

absent_until_created_body()
{
	cloners_init
	vnet_mkjail a
	atf_check -s exit:0 -o not-match:'pflog|pfsync|pflow' jexec a ifconfig -l
	for i in pflog0 pfsync0 pflow0; do
		atf_check -s not-exit:0 -e ignore jexec a ifconfig ${i}
	done
	# Loading and enabling pf creates none either.
	pft_set_rules a "pass all"
	jexec a pfctl -e
	atf_check -s exit:0 -o not-match:'pflog|pfsync|pflow' jexec a ifconfig -l
}

absent_until_created_cleanup()
{
	integ_cleanup
}

# One create/destroy case per cloner.
create_destroy_body()
{
	type=$1
	ifn=${type}$(unit_of ${type})
	cloners_init
	vnet_mkjail a

	atf_check -s exit:0 -o ignore jexec a ifconfig ${ifn} create
	atf_check -s exit:0 -o match:"(^| )${ifn}( |\$)" jexec a ifconfig -l
	atf_check -s exit:0 -o match:"^${ifn}: flags=" jexec a ifconfig ${ifn}
	# Interface group named after the driver (OpenBSD if_clone).
	atf_check -s exit:0 -o match:"groups:.* ${type}" jexec a ifconfig ${ifn}
	# Up and down.
	atf_check -s exit:0 jexec a ifconfig ${ifn} up
	atf_check -s exit:0 -o match:'flags=.*[<,]UP[,>]' jexec a ifconfig ${ifn}
	atf_check -s exit:0 jexec a ifconfig ${ifn} down
	# A second create of the same unit fails.
	atf_check -s not-exit:0 -e ignore jexec a ifconfig ${ifn} create
	atf_check -s exit:0 jexec a ifconfig ${ifn} destroy
	atf_check -s not-exit:0 -e ignore jexec a ifconfig ${ifn}
	atf_check -s exit:0 -o not-match:"(^| )${ifn}( |\$)" jexec a ifconfig -l
	# The unit is free again.
	atf_check -s exit:0 -o ignore jexec a ifconfig ${ifn} create
	atf_check -s exit:0 jexec a ifconfig ${ifn} destroy
}

for _t in pflog pfsync pflow; do
	eval "
atf_test_case \"create_destroy_${_t}\" \"cleanup\"
create_destroy_${_t}_head()
{
	atf_set descr 'Create and destroy a ${_t} interface in a VNET jail'
	atf_set require.user root
}
create_destroy_${_t}_body()
{
	create_destroy_body ${_t}
}
create_destroy_${_t}_cleanup()
{
	integ_cleanup
}
"
done

atf_test_case "pfsync_single_unit" "cleanup"
pfsync_single_unit_head()
{
	atf_set descr 'pfsync has only unit 0'
	atf_set require.user root
}

pfsync_single_unit_body()
{
	cloners_init
	vnet_mkjail a
	atf_check -s not-exit:0 -e ignore jexec a ifconfig pfsync1 create
	atf_check -s exit:0 -o not-match:'pfsync1' jexec a ifconfig -l
	atf_check -s exit:0 -o ignore jexec a ifconfig pfsync0 create
}

pfsync_single_unit_cleanup()
{
	integ_cleanup
}

atf_test_case "per_vnet_names" "cleanup"
per_vnet_names_head()
{
	atf_set descr 'Two VNET jails each create pflog0, pfsync0 and pflow0'
	atf_set require.user root
}

per_vnet_names_body()
{
	cloners_init
	vnet_mkjail a
	vnet_mkjail b
	for j in a b; do
		for i in pflog0 pfsync0 pflow0; do
			atf_check -s exit:0 -o ignore \
			    jexec $j ifconfig ${i} create
		done
	done
	# Destroying in a leaves b's interfaces.
	for i in pflog0 pfsync0 pflow0; do
		atf_check -s exit:0 jexec a ifconfig ${i} destroy
		atf_check -s exit:0 -o match:"^${i}: " jexec b ifconfig ${i}
	done
}

per_vnet_names_cleanup()
{
	integ_cleanup
}

atf_test_case "not_in_host" "cleanup"
not_in_host_head()
{
	atf_set descr 'Interfaces created in a VNET jail are not in the host'
	atf_set require.user root
}

not_in_host_body()
{
	cloners_init
	vnet_mkjail a
	for i in pflog43 pflow43; do
		atf_check -s exit:0 -o ignore jexec a ifconfig ${i} create
		atf_check -s not-exit:0 -e ignore ifconfig ${i}
	done
}

not_in_host_cleanup()
{
	integ_cleanup
}

atf_test_case "destroyed_on_teardown" "cleanup"
destroyed_on_teardown_head()
{
	atf_set descr 'Cloned pf interfaces are destroyed with their VNET, not returned to the host'
	atf_set require.user root
}

destroyed_on_teardown_body()
{
	cloners_init
	vnet_mkjail a
	jexec a ifconfig pflog44 create
	jexec a ifconfig pflow44 create
	jexec a ifconfig pfsync0 create
	jexec a ifconfig lo0 127.0.0.1/8 up
	pft_set_rules a "pass log (to pflog44) all"
	jexec a pfctl -e
	jexec a ping -c 1 127.0.0.1 > /dev/null

	atf_check -s exit:0 jail -r a
	sed -i '' '/^a[[:space:]]*$/d' created_jails.lst

	# Had they been returned to the host vnet, the names would be taken.
	for i in pflog44 pflow44; do
		atf_check -s not-exit:0 -e ignore ifconfig ${i}
		atf_check -s exit:0 -o ignore ifconfig ${i} create
		atf_check -s exit:0 ifconfig ${i} destroy
	done

	# A new VNET under the same name starts without them.
	vnet_mkjail a
	atf_check -s exit:0 -o not-match:'pflog|pfsync|pflow' jexec a ifconfig -l
}

destroyed_on_teardown_cleanup()
{
	for i in pflog44 pflow44; do
		ifconfig ${i} destroy 2>/dev/null
	done
	integ_cleanup
}

atf_test_case "pflog_per_jail" "cleanup"
pflog_per_jail_head()
{
	atf_set descr 'pflog0 in a VNET jail logs that jail only (tcpdump -n -e -ttt -i pflog0)'
	atf_set require.user root
}

pflog_per_jail_body()
{
	pflog_init
	integ_require_prog tcpdump

	vnet_mkjail a
	vnet_mkjail b
	for j in a b; do
		jexec $j ifconfig lo0 127.0.0.1/8 up
		jexec $j ifconfig pflog0 create up
	done
	jexec a ifconfig lo0 inet 203.0.113.1/32 alias
	jexec b ifconfig lo0 inet 203.0.113.2/32 alias
	pft_set_rules a \
	    "block drop log quick proto udp to port 9" \
	    "pass log all"
	pft_set_rules b "pass log all"
	jexec a pfctl -e
	jexec b pfctl -e

	jexec a tcpdump -n -e -ttt -l -i pflog0 > a.txt 2> a.err &
	jexec b tcpdump -n -e -ttt -l -i pflog0 > b.txt 2> b.err &
	sleep 1

	atf_check -s exit:0 -o ignore jexec a ping -c 1 203.0.113.1
	echo x | jexec a nc -u -w 1 203.0.113.1 9 > /dev/null 2>&1
	sleep 1
	jkill() { pkill -j $1 tcpdump; }
	jkill a
	jkill b
	sleep 0.5
	cat a.txt b.txt

	atf_check -o match:'rule [0-9]+/\(match\) pass out on lo0: 203\.0\.113\.1 > 203\.0\.113\.1: icmp: echo request' \
	    cat a.txt
	atf_check -o match:'rule 0/\(match\) block out on lo0: 203\.0\.113\.1\.[0-9]+ > 203\.0\.113\.1\.9: udp' \
	    cat a.txt
	atf_check -o not-match:'203\.0\.113\.1' cat b.txt

	# Now traffic in b only: b logs it, a does not.
	: > a.txt
	jexec a tcpdump -n -e -ttt -l -i pflog0 > a.txt 2> a.err &
	jexec b tcpdump -n -e -ttt -l -i pflog0 > b.txt 2> b.err &
	sleep 1
	atf_check -s exit:0 -o ignore jexec b ping -c 1 203.0.113.2
	sleep 1
	jkill a
	jkill b
	sleep 0.5
	atf_check -o match:'pass out on lo0: 203\.0\.113\.2 > 203\.0\.113\.2: icmp: echo request' \
	    cat b.txt
	atf_check -o not-match:'203\.0\.113\.2' cat a.txt
}

pflog_per_jail_cleanup()
{
	pkill -j a tcpdump 2>/dev/null
	pkill -j b tcpdump 2>/dev/null
	integ_cleanup
}

atf_test_case "no_vnet_move" "cleanup"
no_vnet_move_head()
{
	atf_set descr 'pflog, pfsync and pflow cannot be moved between VNETs (ifconfig vnet / -vnet)'
	atf_set require.user root
}

no_vnet_move_body()
{
	cloners_init
	vnet_mkjail a
	vnet_mkjail b

	# Host to jail (SIOCSIFVNET): refused, the interface stays usable.
	for i in pflog45 pflow45; do
		atf_check -s exit:0 -o ignore ifconfig ${i} create
		atf_check -s not-exit:0 -e ignore ifconfig ${i} vnet b
		atf_check -s exit:0 -o match:"^${i}: " ifconfig ${i}
		atf_check -s not-exit:0 -e ignore jexec b ifconfig ${i}
		atf_check -s exit:0 ifconfig ${i} up
		atf_check -s exit:0 -o match:'flags=.*[<,]UP[,>]' ifconfig ${i}
		atf_check -s exit:0 ifconfig ${i} destroy
	done

	# Jail to host (SIOCSIFRVNET): refused as well.
	for i in pfsync0 pflog46 pflow46; do
		atf_check -s exit:0 -o ignore jexec a ifconfig ${i} create
		atf_check -s not-exit:0 -e ignore ifconfig ${i} -vnet a
		atf_check -s exit:0 -o match:"^${i}: " jexec a ifconfig ${i}
		atf_check -s exit:0 jexec a ifconfig ${i} up
	done
	atf_check -s not-exit:0 -e ignore ifconfig pflog46
	atf_check -s not-exit:0 -e ignore ifconfig pflow46

	# They still work in their own VNET: a logs to pflog46.
	jexec a ifconfig lo0 127.0.0.1/8 up
	pft_set_rules a "pass log (to pflog46) all"
	jexec a pfctl -e
	atf_check -s exit:0 -o ignore jexec a ping -c 1 127.0.0.1
	for i in pfsync0 pflog46 pflow46; do
		atf_check -s exit:0 jexec a ifconfig ${i} destroy
	done
}

no_vnet_move_cleanup()
{
	for i in pflog45 pflow45; do
		ifconfig ${i} destroy 2>/dev/null
	done
	integ_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "absent_until_created"
	for _t in pflog pfsync pflow; do
		atf_add_test_case "create_destroy_${_t}"
	done
	atf_add_test_case "pfsync_single_unit"
	atf_add_test_case "per_vnet_names"
	atf_add_test_case "not_in_host"
	atf_add_test_case "destroyed_on_teardown"
	atf_add_test_case "pflog_per_jail"
	atf_add_test_case "no_vnet_move"
}
