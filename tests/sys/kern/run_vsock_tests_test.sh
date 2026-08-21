#-
# SPDX-License-Identifier: BSD-2-Clause

setup_tree()
{
	helper=$1
	mkdir -p kern/vsock_device_harness kern/vsock_rx_harness mac
	for name in vsock_wire_test vsock_iov_test; do
		ln -s "$helper" "kern/$name"
	done
	for name in vsock_device_test virtio_modern_test virtio_input_test \
	    virtio_rnd_test virtio_rnd_interrupt_test virtio_core_test iov_test \
	    virtio_console_test virtio_9p_test virtio_block_test virtio_net_test \
	    virtio_scsi_test; do
		ln -s "$helper" "kern/vsock_device_harness/$name"
	done
	for name in vsock_rx_test virtio_vsock_transport_test; do
		ln -s "$helper" "kern/vsock_rx_harness/$name"
	done
	ln -s "$helper" mac/mac_capability_isolation_test
}

atf_test_case listing_failure
listing_failure_body()
{
	cat > helper <<'EOF'
#!/bin/sh
exit 9
EOF
	chmod +x helper
	setup_tree "$(pwd)/helper"

	atf_check -s exit:1 -o match:'TOTAL: 0 passed, 18 failed' -e ignore \
	    env BINARY="$(pwd)/helper" CORE_TEST_DIR="$(pwd)/kern" \
	    KERN_TEST_DIR="$(pwd)/kern" \
	    MAC_TEST_DIR="$(pwd)/mac" MAC_CONTROL_PREFLIGHT=no sh \
	    "$(atf_get_srcdir)/run_vsock_tests.sh" "$(pwd)/results"
	atf_check -s exit:0 -o match:'test listing exited with status 9' \
	    grep 'test listing exited with status 9' results
}

atf_test_case case_exit_failure
case_exit_failure_body()
{
	cat > helper <<'EOF'
#!/bin/sh
if [ "$1" = "-l" ]; then
	printf 'ident: vsock_case\n'
	exit 0
fi
printf 'passed\n'
exit 7
EOF
	chmod +x helper
	setup_tree "$(pwd)/helper"

	atf_check -s exit:1 -o match:'TOTAL: 0 passed, 18 failed' -e ignore \
	    env BINARY="$(pwd)/helper" CORE_TEST_DIR="$(pwd)/kern" \
	    KERN_TEST_DIR="$(pwd)/kern" \
	    MAC_TEST_DIR="$(pwd)/mac" MAC_CONTROL_PREFLIGHT=no sh \
	    "$(atf_get_srcdir)/run_vsock_tests.sh" "$(pwd)/results"
	atf_check -s exit:0 -o match:'test case exited with status 7' \
	    grep 'test case exited with status 7' results
}

atf_init_test_cases()
{
	atf_add_test_case listing_failure
	atf_add_test_case case_exit_failure
}
