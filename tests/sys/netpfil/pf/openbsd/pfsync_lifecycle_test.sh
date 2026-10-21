# SPDX-License-Identifier: BSD-2-Clause
# Exercise the OpenBSD hook adapter when FreeBSD marks a syncdev dying
# before notifying its consumers.  Run under INVARIANTS/WITNESS and malloc
# trash checking; absence of jails alone does not prove callback retirement.
. $(atf_get_srcdir)/../../../common/vnet.subr

lifecycle_head()
{
 atf_set require.user root
 atf_set is.exclusive true
 atf_set timeout 900
}
lifecycle_init()
{
 vnet_init
 kldstat -q -m pf || atf_skip 'pf is not loaded'
}
lifecycle_pair()
{
 ep=$(vnet_mkepair)
 ifconfig ${ep}a inet 192.0.2.2/24 up
 vnet_mkjail "$1" ${ep}b
 jexec "$1" ifconfig ${ep}b inet 192.0.2.1/24 up
 jexec "$1" pfctl -e
 jexec "$1" ifconfig pfsync0 create
 jexec "$1" ifconfig pfsync0 syncdev ${ep}b syncpeer 192.0.2.2 up
}
atf_test_case syncdev_detach cleanup
syncdev_detach_head()
{
 lifecycle_head
 atf_set descr 'Departing sync interfaces retire hooks before pfsync storage is reused'
}
syncdev_detach_body()
{
 lifecycle_init
 for n in $(jot 8); do
  name=pslife${n}
  lifecycle_pair "$name"
  atf_check -s exit:0 -o empty -e empty ifconfig ${ep}a destroy
  atf_check -s exit:0 -o empty -e empty jexec "$name" ifconfig pfsync0 destroy
  # Reuse pfsync storage before the next interface/link event.
  atf_check -s exit:0 -o empty -e empty jexec "$name" ifconfig pfsync0 create
  atf_check -s exit:0 -o empty -e empty jexec "$name" ifconfig pfsync0 destroy
  atf_check -s exit:0 -o empty -e empty jail -r "$name"
  echo "SYNCDEV_ITERATION=$n"
 done
}
syncdev_detach_cleanup() { vnet_cleanup; }
atf_test_case vnet_teardown cleanup
vnet_teardown_head()
{
 lifecycle_head
 atf_set descr 'VNET teardown drains pfsync hook and timeout work before recreation'
}
vnet_teardown_body()
{
 lifecycle_init
 for n in $(jot 8); do
  name=psvnet${n}
  lifecycle_pair "$name"
  atf_check -s exit:0 -o empty -e empty jail -r "$name"
  # The peer returned from its VNET; destroy it before allocating the next.
  atf_check -s exit:0 -o empty -e empty ifconfig ${ep}a destroy
  echo "VNET_ITERATION=$n"
 done
}
vnet_teardown_cleanup() { vnet_cleanup; }
atf_init_test_cases()
{
 atf_add_test_case syncdev_detach
 atf_add_test_case vnet_teardown
}
