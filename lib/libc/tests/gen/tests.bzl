# SPDX-License-Identifier: BSD-2-Clause
"""Original general libc programs, static login test and package-owned DSO."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library", "cc_shared_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_copy_file")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_SOURCE = "//contrib/netbsd-tests/lib/libc/gen:"
_DIRECTORY = "/usr/tests/lib/libc/gen"
_LOCAL = ['arc4random_test',
 'dir2_test',
 'dlopen_empty_test',
 'fmtcheck2_test',
 'fmtmsg_test',
 'fnmatch2_test',
 'fpclassify_test',
 'fpclassify2_test',
 'fts_blocks_test',
 'fts_capsicum_test',
 'fts_children_test',
 'fts_misc_test',
 'fts_open_test',
 'fts_openat_test',
 'fts_options_test',
 'fts_regress_test',
 'fts_set_test',
 'fpsetmask_test',
 'fpsetround_test',
 'ftw_test',
 'getentropy_test',
 'getmntinfo_test',
 'glob2_test',
 'glob_blocks_test',
 'limits_test',
 'makecontext_test',
 'opendir_test',
 'popen_test',
 'pututxline_test',
 'posix_spawn_test',
 'realpath2_test',
 'scandir_test',
 'scandir_blocks_test',
 'sig2str_test',
 'sigsetops_test',
 'wordexp_test']
_IMPORTED = ['alarm_test',
 'assert_test',
 'basedirname_test',
 'cpuset_test',
 'dir_test',
 'floatunditf_test',
 'fnmatch_test',
 'ftok_test',
 'getcwd_test',
 'getgrent_test',
 'glob_test',
 'humanize_number_test',
 'isnan_test',
 'nice_test',
 'pause_test',
 'raise_test',
 'realpath_test',
 'setdomainname_test',
 'sethostname_test',
 'sleep_test',
 'syslog_test',
 'time_test',
 'ttyname_test',
 'vis_test']
_CASES = {'arc4random_test': ['test_arc4random', 'test_arc4random_uniform'],
 'dir2_test': ['telldir_after_seekdir', 'telldir_at_end_of_block'],
 'dlopen_empty_test': ['dlopen_empty_test'],
 'fmtcheck2_test': ['fmtcheck_test'],
 'fmtmsg_test': ['fmtmsg_test'],
 'fnmatch2_test': ['fnmatch_test',
                   'fnmatch_collsym',
                   'fnmatch_characterclass',
                   'fnmatch_equivclass'],
 'fpclassify_test': ['no_test'],
 'fpclassify2_test': ['test_fpclassify'],
 'fts_blocks_test': ['fts_blocks_test'],
 'fts_capsicum_test': ['fts_dirfd_valid', 'fts_dirfd_capsicum', 'fts_dirfd_deep_tree'],
 'fts_children_test': ['before_read',
                       'empty_dir',
                       'nonempty_dir',
                       'called_twice',
                       'nameonly',
                       'nondirectory',
                       'invalid_options'],
 'fts_misc_test': ['fts_unrdir',
                   'fts_unrdir_nochdir',
                   'nochdir_app_can_chdir',
                   'name_nul_terminated',
                   'prepost_order_and_levels',
                   'ftsent_fields',
                   'symlink_loop_physical',
                   'cycle_detection',
                   'close_after_root_deleted',
                   'close_after_root_moved',
                   'nochdir_empty_terminal_dir',
                   'ns_errno_set',
                   'xdev',
                   'no_fd_leak_on_early_close'],
 'fts_open_test': ['invalid_options',
                   'empty_argv',
                   'empty_path_string',
                   'nonexistent_path',
                   'trailing_slash',
                   'unreadable_dir',
                   'multiple_roots'],
 'fts_openat_test': ['atfdcwd_matches_fts_open', 'openat_capsicum', 'fts_dirfd_openat'],
 'fts_options_test': ['fts_options_logical',
                      'fts_options_logical_nostat',
                      'fts_options_logical_seedot',
                      'fts_options_physical',
                      'fts_options_physical_nochdir',
                      'fts_options_physical_comfollow',
                      'fts_options_physical_comfollowdir',
                      'fts_options_physical_nostat',
                      'fts_options_physical_nostat_type',
                      'fts_options_physical_seedot'],
 'fts_regress_test': ['read_no_exec_dir',
                      'no_slnone_for_nonsymlink',
                      'readdir_error_detected',
                      'odirectory_changedir',
                      'concurrent_modification',
                      'accpath_correct_after_descent',
                      'trailing_slash_children'],
 'fts_set_test': ['invalid_options',
                  'again',
                  'again_consecutive',
                  'follow_symlink_to_file',
                  'follow_symlink_to_dir',
                  'follow_dead_symlink',
                  'skip',
                  'clientptr_roundtrip',
                  'get_stream_backpointer'],
 'fpsetmask_test': ['no_test'],
 'fpsetround_test': ['fpsetround_basic'],
 'ftw_test': ['ftw_test'],
 'getentropy_test': ['getentropy_count', 'getentropy_fault', 'getentropy_sizes'],
 'getmntinfo_test': ['getmntinfo_test'],
 'glob2_test': ['glob_pathological_test', 'glob_period', 'glob_callback'],
 'glob_blocks_test': ['glob_b_callback'],
 'limits_test': ['dummy'],
 'makecontext_test': ['makecontext_arg1',
                      'makecontext_arg2',
                      'makecontext_arg3',
                      'makecontext_arg4',
                      'makecontext_arg5',
                      'makecontext_arg6'],
 'opendir_test': ['opendir_ok',
                  'fdopendir_ok',
                  'fdopendir_ebadf',
                  'fdopendir_enotdir',
                  'opendir_fifo'],
 'popen_test': ['popen_all_modes_test',
                'popen_rmodes_test',
                'popen_wmodes_test',
                'popen_rwmodes_test'],
 'pututxline_test': ['boot_shutdown_records',
                     'boot_active_error',
                     'shutdown_active_error',
                     'lastlogin_error',
                     'short_boot_write',
                     'lastlogin_upgrade',
                     'short_history_write',
                     'active_flush_error',
                     'lastlogin_flush_error',
                     'logout_flush_error',
                     'session_records'],
 'posix_spawn_test': ['posix_spawn_simple_test',
                      'posix_spawn_no_such_command_negative_test',
                      'posix_spawnp_enoexec_fallback',
                      'posix_spawnp_enoexec_fallback_null_argv0',
                      'posix_spawnp_eacces',
                      'posix_spawnp_stackunderflow'],
 'realpath2_test': ['realpath_null',
                    'realpath_empty',
                    'realpath_buffer_overflow',
                    'realpath_empty_symlink',
                    'realpath_partial'],
 'scandir_test': ['scandir_test',
                  'fdscandir_test',
                  'scandirat_test',
                  'scandir_none',
                  'scandir_error'],
 'scandir_blocks_test': ['scandir_b_test', 'fdscandir_b_test', 'scandirat_b_test'],
 'sig2str_test': ['sig2str_valid',
                  'sig2str_invalid',
                  'str2sig_rtmin_rtmax',
                  'str2sig_invalid_rt',
                  'str2sig_fullname',
                  'str2sig_lowercase',
                  'str2sig_numeric',
                  'str2sig_invalid'],
 'sigsetops_test': ['posix_sigsetop_test', 'extended_sigsetop_test'],
 'wordexp_test': ['simple_test',
                  'long_output_test',
                  'WRDE_DOOFFS_test',
                  'WRDE_REUSE_test',
                  'WRDE_APPEND_test',
                  'WRDE_DOOFFS__WRDE_APPEND_test',
                  'WRDE_UNDEF_test',
                  'WRDE_NOCMD_test',
                  'WRDE_BADCHAR_test',
                  'WRDE_SYNTAX_test',
                  'with_SIGCHILD_handler_test',
                  'with_SIGCHILD_ignore_test',
                  'with_unused_non_default_IFS_test',
                  'with_used_non_default_IFS_test'],
 'alarm_test': ['alarm_basic', 'alarm_fork', 'alarm_previous'],
 'assert_test': ['assert_false', 'assert_true'],
 'basedirname_test': ['basename_posix', 'dirname_posix'],
 'cpuset_test': ['cpuset_err', 'cpuset_set', 'cpuset_size'],
 'dir_test': ['seekdir_basic', 'telldir_leak'],
 'floatunditf_test': ['floatunditf'],
 'fnmatch_test': ['fnmatch_backslashes',
                  'fnmatch_casefold',
                  'fnmatch_leadingdir',
                  'fnmatch_noescape',
                  'fnmatch_pathname',
                  'fnmatch_period',
                  'fnmatch_initialbracket'],
 'ftok_test': ['ftok_err', 'ftok_link'],
 'getcwd_test': ['getcwd_err', 'getcwd_fts'],
 'getgrent_test': ['getgrent_loop', 'getgrent_setgid'],
 'glob_test': ['glob_star_not'],
 'humanize_number_test': ['humanize_number_basic', 'humanize_number_big'],
 'isnan_test': ['isnan_basic', 'isinf_basic'],
 'nice_test': ['nice_err', 'nice_priority', 'nice_root', 'nice_thread'],
 'pause_test': ['pause_basic', 'pause_kill'],
 'raise_test': ['raise_err', 'raise_ret', 'raise_sig', 'raise_stress'],
 'realpath_test': ['realpath_basic', 'realpath_huge', 'realpath_symlink'],
 'setdomainname_test': ['setdomainname_basic', 'setdomainname_limit', 'setdomainname_perm'],
 'sethostname_test': ['sethostname_basic', 'sethostname_limit', 'sethostname_perm'],
 'sleep_test': ['nanosleep', 'select', 'sleep', 'kevent'],
 'syslog_test': ['syslog_pthread'],
 'time_test': ['time_copy', 'time_mono', 'time_timeofday'],
 'ttyname_test': ['ttyname_err', 'ttyname_r_err', 'ttyname_r_stdin', 'ttyname_stdin'],
 'vis_test': ['strvis_basic',
              'strvis_null',
              'strvis_empty',
              'strunvis_hex',
              'strvis_locale',
              'strvis_overflow_mb',
              'strvis_overflow_c']}
_CLEANUP = {'fts_misc_test': ['xdev'],
 'ftok_test': ['ftok_link'],
 'setdomainname_test': ['setdomainname_basic', 'setdomainname_limit'],
 'sethostname_test': ['sethostname_basic', 'sethostname_limit', 'sethostname_perm']}
_USERS = {'fts_misc_test': {'fts_unrdir': 'unprivileged',
                   'fts_unrdir_nochdir': 'unprivileged',
                   'xdev': 'root'},
 'fts_open_test': {'unreadable_dir': 'unprivileged'},
 'fts_regress_test': {'read_no_exec_dir': 'unprivileged', 'readdir_error_detected': 'unprivileged'},
 'glob2_test': {'glob_callback': 'unprivileged'},
 'glob_blocks_test': {'glob_b_callback': 'unprivileged'},
 'pututxline_test': {'boot_shutdown_records': 'root',
                     'boot_active_error': 'root',
                     'shutdown_active_error': 'root',
                     'lastlogin_error': 'root',
                     'short_boot_write': 'root',
                     'lastlogin_upgrade': 'root',
                     'short_history_write': 'root',
                     'active_flush_error': 'root',
                     'lastlogin_flush_error': 'root',
                     'logout_flush_error': 'root',
                     'session_records': 'root'},
 'posix_spawn_test': {'posix_spawnp_eacces': 'unprivileged'},
 'realpath2_test': {'realpath_partial': 'unprivileged'},
 'getgrent_test': {'getgrent_setgid': 'root'},
 'nice_test': {'nice_err': 'unprivileged', 'nice_root': 'root'},
 'setdomainname_test': {'setdomainname_basic': 'root',
                        'setdomainname_limit': 'root',
                        'setdomainname_perm': 'unprivileged'},
 'sethostname_test': {'sethostname_basic': 'root',
                      'sethostname_limit': 'root',
                      'sethostname_perm': 'unprivileged'}}
_TIMEOUTS = {'sleep_test': {'nanosleep': 65, 'select': 65, 'sleep': 65, 'kevent': 65},
 'syslog_test': {'syslog_pthread': 2}}
_HOST_CASES = {'arc4random_test': ['test_arc4random', 'test_arc4random_uniform'],
 'getentropy_test': ['getentropy_count', 'getentropy_fault', 'getentropy_sizes'],
 'makecontext_test': ['makecontext_arg1',
                      'makecontext_arg2',
                      'makecontext_arg3',
                      'makecontext_arg4',
                      'makecontext_arg5',
                      'makecontext_arg6'],
 'opendir_test': ['opendir_ok',
                  'fdopendir_ok',
                  'fdopendir_ebadf',
                  'fdopendir_enotdir',
                  'opendir_fifo'],
 'dir2_test': ['telldir_after_seekdir', 'telldir_at_end_of_block'],
 'fmtcheck2_test': ['fmtcheck_test'],
 'fpclassify_test': ['no_test'],
 'fpclassify2_test': ['test_fpclassify'],
 'fpsetround_test': ['fpsetround_basic'],
 'sig2str_test': ['sig2str_valid',
                  'sig2str_invalid',
                  'str2sig_rtmin_rtmax',
                  'str2sig_invalid_rt',
                  'str2sig_fullname',
                  'str2sig_lowercase',
                  'str2sig_numeric',
                  'str2sig_invalid'],
 'sigsetops_test': ['posix_sigsetop_test', 'extended_sigsetop_test'],
 'basedirname_test': ['basename_posix', 'dirname_posix'],
 'humanize_number_test': ['humanize_number_basic', 'humanize_number_big'],
 'isnan_test': ['isnan_basic', 'isinf_basic']}
_OLD_CASE_ALIASES = {'native_opendir_ok': 'opendir_ok',
 'native_fdopendir_ok': 'fdopendir_ok',
 'native_fdopendir_ebadf': 'fdopendir_ebadf',
 'native_fdopendir_enotdir': 'fdopendir_enotdir',
 'native_opendir_fifo': 'opendir_fifo',
 'native_telldir_after_seekdir': 'telldir_after_seekdir',
 'native_telldir_at_end_of_block': 'telldir_at_end_of_block',
 'native_posix_sigsetop_test': 'posix_sigsetop_test',
 'native_extended_sigsetop_test': 'extended_sigsetop_test',
 'native_sig2str_valid': 'sig2str_valid',
 'native_sig2str_invalid': 'sig2str_invalid',
 'native_str2sig_rtmin_rtmax': 'str2sig_rtmin_rtmax',
 'native_str2sig_invalid_rt': 'str2sig_invalid_rt',
 'native_str2sig_fullname': 'str2sig_fullname',
 'native_str2sig_lowercase': 'str2sig_lowercase',
 'native_str2sig_numeric': 'str2sig_numeric',
 'native_str2sig_invalid': 'str2sig_invalid',
 'native_getentropy_count': 'getentropy_count',
 'native_getentropy_fault': 'getentropy_fault',
 'native_getentropy_sizes': 'getentropy_sizes',
 'native_makecontext_arg1': 'makecontext_arg1',
 'native_makecontext_arg2': 'makecontext_arg2',
 'native_makecontext_arg3': 'makecontext_arg3',
 'native_makecontext_arg4': 'makecontext_arg4',
 'native_makecontext_arg5': 'makecontext_arg5',
 'native_makecontext_arg6': 'makecontext_arg6',
 'native_test_arc4random': 'test_arc4random',
 'native_test_arc4random_uniform': 'test_arc4random_uniform'}
_OLD_PROGRAM_ALIASES = ['makecontext', 'opendir', 'dir2', 'sigsetops', 'sig2str', 'getentropy', 'arc4random']

def gen_tests():
    cc_import(name = "atf_interface", shared_library = "//lib/atf/libatf-c:atf_c_shared", deps = ["//contrib/atf:c_headers"])
    cc_import(name = "atf_static_interface", static_library = "//lib/atf/libatf-c:static_archive", deps = ["//contrib/atf:c_headers"])
    for name, library, headers in [("m", "//lib/msun:m_shared", []), ("thr", "//lib/libthr:thr_shared", []),
        ("util", "//lib/libutil:util_shared", ["//lib/libutil:headers"]), ("blocks", "//lib/libblocksruntime:blocks_shared", [])]:
        cc_import(name = name + "_interface", shared_library = library, deps = headers)
    cc_library(name = "fts_headers", hdrs = ["fts_test.h"], includes = ["."])
    cc_library(name = "fnmatch_headers", hdrs = ["fnmatch_testcases.h"], includes = ["."])
    # This child Makefile produces only a shared library, not a static archive.
    cc_library(name = "dummy_objects", srcs = ["//lib/libc/tests/gen/libdummy:libdummy.c"],
        deps = ["//lib/libc:shared_abi_interface"],
        copts = [f for f in libc_test_copts(6) if f != "-fPIE"], features = ["bsd_small_pic"], linkstatic = True,
        target_compatible_with = _PLATFORM)
    cc_shared_library(name = "dummy_shared", deps = [":dummy_objects"], shared_lib_name = "libdummy.so.0",
        user_link_flags = ["-nodefaultlibs", "-Wl,-soname,libdummy.so.0", "-Wl,--fatal-warnings,--warn-shared-textrel"], target_compatible_with = _PLATFORM)
    bsd_debug_split(name = "dummy_debug", src = ":dummy_shared", binary_name = "install/libdummy.so.0", debug_name = "install/libdummy.so.0.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    native.filegroup(name = "dummy_symbols", srcs = [":dummy_debug"], output_group = "debug_files")
    bsd_copy_file(name = "spawn_fixture", src = "spawnp_enoexec.sh", output = "fixtures/spawnp_enoexec.sh", make_executable = True,
        cat = "@bsd_sdk//toolchain:cat", runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    entries = []
    for name, source, destination, tags in [
        ("dummy", ":dummy_debug", _DIRECTORY + "/libdummy.so.0", ["package=utilities"]),
        ("dummy_symbols", ":dummy_symbols", "/usr/lib/debug" + _DIRECTORY + "/libdummy.so.0.debug", ["package=utilities", "dbg"]),
        ("spawn_script", ":spawn_fixture", _DIRECTORY + "/spawnp_enoexec.sh", ["package=tests"]),
    ]:
        bsd_install_file(name = name + "_entry", src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0755" if name == "spawn_script" else "0444", install_tags = tags)
        entries.append(":" + name + "_entry")
    bsd_install_link(name = "dummy_alias", destination = _DIRECTORY + "/libdummy.so", target = "libdummy.so.0", kind = "symlink",
        owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    entries.append(":dummy_alias")
    manifests = []
    host = []
    deferred = []
    for program in _LOCAL + _IMPORTED:
        imported = program in _IMPORTED
        static = program == "pututxline_test"
        blocks = program in ["fts_blocks_test", "glob_blocks_test", "scandir_blocks_test"]
        source = _SOURCE + "t_" + program[:-5] + ".c" if imported else {"fmtcheck2_test": "fmtcheck_test.c", "fnmatch2_test": "fnmatch_test.c"}.get(program, program + ".c")
        deps = [":atf_static_interface"] if static else [":atf_interface"]
        if imported:
            deps += ["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"]
        if program in ["fts_open_test", "fts_misc_test", "fts_options_test"]:
            deps.append(":fts_headers")
        if program == "fnmatch2_test":
            deps.append(":fnmatch_headers")
        if program == "sleep_test":
            deps.append(_SOURCE + "isqemu")
        if program == "getentropy_test":
            deps.append("//include:libc_gen_entropy_headers")
        if program in ["fpclassify_test", "fpsetround_test"]:
            deps.append(":m_interface")
        if program == "humanize_number_test":
            deps.append(":util_interface")
        if program in ["nice_test", "fts_regress_test", "syslog_test"]:
            deps.append(":thr_interface")
        if blocks:
            deps.append(":blocks_interface")
        deps.append("//lib/libc:static_link_objects" if static else "//lib/libc:shared_abi_interface")
        bsd_link_sequence(name = program + "_link", deps = deps)
        copts = [f for f in libc_test_copts() if not static or f != "-fPIE"] + (["-fblocks"] if blocks else [])
        cc_binary(name = program, srcs = [source], deps = [":" + program + "_link"], copts = copts,
            defines = ["TEST_LONG_DOUBLE", "__HAVE_LONG_DOUBLE"] + ([] if static else ["PIC"]),
            linkopts = ["-nodefaultlibs"] + (["-static"] if static else ["-pie"]),
            features = ["fully_static_link"] if static else [], linkstatic = True, target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
        for case in _CASES[program]:
            selected = case in _HOST_CASES.get(program, [])
            timeout = _TIMEOUTS.get(program, {}).get(case, 0)
            name = program + "_" + case + "_runtime"
            bsd_atf_test(name = name, body = ":" + program, case_name = case, interface = "program",
                runtime_lib = ([] if static else LIBC_TEST_RUNTIME) + (["//lib/msun:m_shared"] if program in ["fpclassify_test", "fpsetround_test"] else []) +
                    (["//lib/libutil:util_shared"] if program == "humanize_number_test" else []) +
                    (["//lib/libthr:thr_shared"] if program in ["nice_test", "fts_regress_test", "syslog_test"] else []) +
                    (["//lib/libblocksruntime:blocks_shared"] if blocks else []),
                data_paths = {":dummy_shared": "libdummy.so", ":spawn_fixture": "spawnp_enoexec.sh"} if program == "posix_spawn_test" else {},
                required_user = _USERS.get(program, {}).get(case, ""), cleanup = case in _CLEANUP.get(program, []), body_timeout_seconds = timeout,
                tags = ([] if selected else ["manual", "external", "no-remote"]) + (["exclusive"] if program == "setdomainname_test" else []),
                runner = "//tools/build/bazel:atf_runner", test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"},
                size = "large" if timeout >= 300 else ("medium" if timeout >= 60 else "small"), target_compatible_with = _PLATFORM)
            (host if selected else deferred).append(":" + name)
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(_CASES.keys()), interfaces = {p: "atf" for p in _CASES},
        metadata = {"setdomainname_test": json.encode({"is_exclusive": True})}, subdirectories = ["execve", "posix_spawn"])
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = entries + [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive", "//lib/libc/tests/gen/execve:installation_archives", "//lib/libc/tests/gen/posix_spawn:installation_archives"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "runtime_tests", tests = host)
    native.test_suite(name = "deferred_runtime_tests", tests = deferred, tags = ["manual"])
    for program in _OLD_PROGRAM_ALIASES:
        native.alias(name = program + "_runtime_program", actual = ":" + program + "_test")
    for alias, case in _OLD_CASE_ALIASES.items():
        matches = [p for p in _HOST_CASES if case in _HOST_CASES[p]]
        if len(matches) != 1:
            fail("legacy case alias must resolve to one selected original case")
        native.alias(name = alias, actual = ":" + matches[0] + "_" + case + "_runtime", visibility = ["//visibility:public"])
