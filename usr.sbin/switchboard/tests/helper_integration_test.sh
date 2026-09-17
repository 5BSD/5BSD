#!/usr/libexec/atf-sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# End-to-end coverage for private helper sub-services (service_helper_open).
# A parent unit opens a helper declared in its own bundle by short unit name;
# switchboard resolves the synthetic bundle-local provider name
# "helper.<bundle-id>.<unit>", drives an on-demand launch of the helper, and
# hands the parent a confined channel to it.  The reserved "helper." namespace
# must be reachable ONLY through this path — never a global lookup.

helpers="$(dirname "$0")/test_helpers.sh"
if [ ! -r "${helpers}" ]; then
	helpers="@SRCTOP@/usr.sbin/switchboard/tests/test_helpers.sh"
fi
. "${helpers}"

# Install a two-unit bundle sharing one bundle_id: a boot-start parent and an
# on-demand private helper.  The helper name resolution keys off a shared
# bundle_id, so both units MUST live in the same .cap.
#
# Usage: install_helper_bundle <bundle_id> <parent_args_ucl> <helper_ucl>
install_helper_bundle()
{
	local bid="$1" parent_args="$2" helper_ucl="$3"
	local dir="${APPS_DIR}/Helper.cap"
	local fixture

	find_capd_service_fixture
	fixture="${capd_service_fixture}"

	mkdir -p "${dir}/Units/parent.unit/bin" \
	    "${dir}/Units/probe.unit/bin"
	cat > "${dir}/Bundle.ucl" <<-UCL
	schema = "org.5bsd.capability-bundle";
	schema_version = 1;
	bundle_id = "${bid}";
	version = "1.0.0";
	sequence = 1;
	author = "test";
	publisher = "org.test";
	units = ["parent", "probe"];
	UCL

	cat > "${dir}/Units/parent.unit/Unit.ucl" <<-UCL
	activation { boot = true; }
	restart = "never";
	directories = ["${WORK}"];
	${parent_args}
	UCL
	cp "${fixture}" "${dir}/Units/parent.unit/bin/parent"
	chmod 0555 "${dir}/Units/parent.unit/bin/parent"

	cat > "${dir}/Units/probe.unit/Unit.ucl" <<-UCL
	${helper_ucl}
	restart = "never";
	directories = ["${WORK}"];
	arguments = ["helper-provider", "helper-probe.out"];
	UCL
	cp "${fixture}" "${dir}/Units/probe.unit/bin/probe"
	chmod 0555 "${dir}/Units/probe.unit/bin/probe"

	echo "${dir}"
}

helper_test_head()
{
	atf_set "require.user" "root"
	require_capsule_stack_kmods
	atf_set "timeout" "60"
}

atf_test_case launch_and_connect cleanup
launch_and_connect_head()
{
	atf_set "descr" \
	    "a parent opens a private helper by unit name; switchboard launches it on demand and delivers a live confined channel"
	helper_test_head
}
launch_and_connect_body()
{
	local parent_result probe_result

	require_mac_capability
	find_capd_service_fixture
	start_stack
	parent_result="${WORK}/helper-parent.out"
	probe_result="${WORK}/helper-probe.out"
	install_helper_bundle "org.test.helper" \
	    "arguments = [\"helper-open\", \"probe\", \"helper-parent.out\"];" \
	    'activation { helper = true; }'
	reload_stack

	wait_for_file "${parent_result}" 20 ||
	    atf_fail "parent did not complete helper_open"
	atf_check -s exit:0 -o match:'helper_open=ok' \
	    cat "${parent_result}"
	atf_check -s exit:0 -o match:'received=pong' \
	    grep 'received=pong' "${parent_result}"
	# The delivered client endpoint must be transfer-confined (CAP_XFER_NONE).
	atf_check -s exit:0 -o match:'confined=1' \
	    grep 'confined=1' "${parent_result}"

	# The helper itself launched on demand and exposed exactly its synthetic
	# bundle-local name.
	wait_for_file "${probe_result}" 20 ||
	    atf_fail "helper did not launch and expose"
	atf_check -s exit:0 -o match:'helper=exposed' \
	    grep 'helper=exposed' "${probe_result}"
	atf_check -s exit:0 -o match:'name=helper.org.test.helper.probe' \
	    grep 'name=helper.org.test.helper.probe' "${probe_result}"
	stop_stack
}
launch_and_connect_cleanup()
{
	cleanup_common
}

atf_test_case open_undeclared cleanup
open_undeclared_head()
{
	atf_set "descr" \
	    "opening a helper unit that the bundle does not declare fails with ENOENT and launches nothing"
	helper_test_head
}
open_undeclared_body()
{
	local parent_result probe_result

	require_mac_capability
	find_capd_service_fixture
	start_stack
	parent_result="${WORK}/helper-parent.out"
	probe_result="${WORK}/helper-probe.out"
	# The parent asks for a helper unit ("ghost") that is not in the bundle.
	install_helper_bundle "org.test.helper" \
	    "arguments = [\"helper-open\", \"ghost\", \"helper-parent.out\"];" \
	    'activation { helper = true; }'
	reload_stack

	wait_for_file "${parent_result}" 20 ||
	    atf_fail "parent did not record its failed helper_open"
	atf_check -s exit:0 -o match:'helper_open=failed' \
	    grep 'helper_open=failed' "${parent_result}"
	# No such synthetic name -> on-demand resolution reports ENOENT (2).
	atf_check -s exit:0 -o match:'errno=2' \
	    grep 'errno=2' "${parent_result}"
	# The declared helper must NOT have been launched.
	atf_check -s exit:1 -o empty -e empty test -s "${probe_result}"
	stop_stack
}
open_undeclared_cleanup()
{
	cleanup_common
}

atf_init_test_cases()
{
	atf_add_test_case launch_and_connect
	atf_add_test_case open_undeclared
}
