#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# End-to-end bring-up of the virtual HCI controller with ZERO hardware.
#
# These tests are kernel-gated: they require root and a loadable
# ng_hci_virt(4) module, so they are skipped on a build host and exercised
# only on a running kernel (developer rig / CI VM), matching the other
# netgraph tests in this directory.
#
# The keystone assertion is that a Read_BD_ADDR command issued through the
# ordinary raw-HCI path (hccontrol -n vhci0, i.e. the exact path blued(8)
# uses) travels down through ng_hci to the virtual controller, is answered
# by the userspace emulator, and returns the emulator's programmed address.
# If that round-trip succeeds, the stack cannot tell the virtual controller
# from a real adapter.

VHCITOOL=/usr/sbin/vhcitool

# Load ng_hci_virt, skipping the whole test if it is unavailable.
require_vhci()
{
	if ! kldstat -q -n ng_hci_virt; then
		kldload ng_hci_virt 2>/dev/null || \
		    atf_skip "ng_hci_virt module not available"
	fi
	if [ ! -c /dev/vhci ]; then
		atf_skip "/dev/vhci control device not present"
	fi
	if [ ! -x "$VHCITOOL" ]; then
		atf_skip "vhcitool not installed"
	fi
}

# Wait up to ~5s for a shell condition to become true.
wait_for()
{
	local i=0
	while [ $i -lt 50 ]; do
		if eval "$1"; then
			return 0
		fi
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

atf_test_case "bringup" "cleanup"
bringup_head()
{
	atf_set descr 'A virtual controller is indistinguishable to the stack'
	atf_set require.user root
}
bringup_body()
{
	require_vhci

	# Spin up one virtual controller; vhcitool wires ng_hci and names
	# the adapter node "vhci0hci" so hccontrol -n vhci0 resolves it.
	$VHCITOOL -n 1 >vhcitool.out 2>&1 &
	echo $! >vhcitool.pid

	atf_check -o ignore wait_for '[ -c /dev/vhci0 ]'
	atf_check -o ignore wait_for 'ngctl info vhci0hci: >/dev/null 2>&1'

	# The keystone: a Read_BD_ADDR round-trip through the full stack.
	atf_check -s exit:0 -o match:'BD_ADDR' \
	    hccontrol -n vhci0 read_bd_addr
}
bringup_cleanup()
{
	if [ -f vhcitool.pid ]; then
		kill "$(cat vhcitool.pid)" 2>/dev/null
	fi
	sleep 0.2
	ngctl shutdown vhci0hci: 2>/dev/null
	true
}

atf_test_case "linked_pair" "cleanup"
linked_pair_head()
{
	atf_set descr 'Two linked virtual controllers both attach to the stack'
	atf_set require.user root
}
linked_pair_body()
{
	require_vhci

	$VHCITOOL -n 2 -l >vhcitool.out 2>&1 &
	echo $! >vhcitool.pid

	atf_check -o ignore wait_for '[ -c /dev/vhci0 ] && [ -c /dev/vhci1 ]'
	atf_check -o ignore wait_for 'ngctl info vhci0hci: >/dev/null 2>&1'
	atf_check -o ignore wait_for 'ngctl info vhci1hci: >/dev/null 2>&1'

	atf_check -s exit:0 -o match:'BD_ADDR' hccontrol -n vhci0 read_bd_addr
	atf_check -s exit:0 -o match:'BD_ADDR' hccontrol -n vhci1 read_bd_addr
}
linked_pair_cleanup()
{
	if [ -f vhcitool.pid ]; then
		kill "$(cat vhcitool.pid)" 2>/dev/null
	fi
	sleep 0.2
	ngctl shutdown vhci0hci: 2>/dev/null
	ngctl shutdown vhci1hci: 2>/dev/null
	true
}

atf_init_test_cases()
{
	atf_add_test_case "bringup"
	atf_add_test_case "linked_pair"
}
