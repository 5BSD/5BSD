# SPDX-License-Identifier: BSD-2-Clause
TESTDIR = "/usr/tests/usr.sbin/BSDFilesystem"
ATF_PROGRAMS = ['abort_test', 'anchor_test', 'cleanup_test', 'config_test', 'evolution_test', 'lifecycle_test', 'manifest_test', 'namespace_test', 'oes_factory_failure_test', 'oes_factory_test', 'oes_handoff_test', 'oes_session_test', 'persistent_retention_test', 'provider_test', 'quota_test', 'staging_recovery_test']
BINARIES = ATF_PROGRAMS + ["next_peer", "latency_bench"]
DIRECTORIES = ({d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=tzfs-tests"]}'
    for d in [TESTDIR, "/usr/share/licenses/tzfs-tests", "/usr/share/licenses/tzfs-tests/fuchsia"]} |
    {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=tzfs-tests","dbg"]}'
    for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/usr.sbin", "/usr/lib/debug" + TESTDIR]})
MANIFESTS = ["//usr.sbin/BSDFilesystem/tests:install_" + p for p in BINARIES] + ["//usr.sbin/BSDFilesystem/tests:install_extra"]
