# SPDX-License-Identifier: BSD-2-Clause
"""Original stdlib programs, dlopen libraries, Blocks dependencies and installation."""
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import", "cc_library", "cc_shared_library")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper", "bsd_debug_split")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//lib/libc:test_policy.bzl", "libc_test_copts", "libc_test_cxx_copts")
load("//lib/libc:test_runtime.bzl", "LIBC_TEST_RUNTIME")
load("//share/monetdef_unicode:locales.bzl", MONETARY = "LOCALES", MONETARY_ALIASES = "ALIASES")
load("//share/numericdef_unicode:locales.bzl", NUMERIC = "LOCALES", NUMERIC_ALIASES = "ALIASES")
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_SOURCE = "//contrib/netbsd-tests/lib/libc/stdlib:"
_DIRECTORY = "/usr/tests/lib/libc/stdlib"
_LOCAL = ['free_sized_test', 'bsearch_test', 'bsearch_b_test', 'bsearch_s_test', 'clearenv_test', 'cxa_atexit_test', 'dynthr_test', 'getenv_r_test', 'heapsort_test', 'libc_exit_test', 'mergesort_test', 'qsort_test', 'qsort_b_test', 'qsort_r_compat_test', 'qsort_r_test', 'qsort_s_test', 'qsort_bench', 'set_constraint_handler_s_test', 'strfmon_test', 'strfrom_test', 'system_test', 'tsearch_test']
_IMPORTED = ['abs_test', 'atoi_test', 'div_test', 'getenv_test', 'exit_test', 'hsearch_test', 'posix_memalign_test', 'random_test', 'strtod_test', 'strtol_test']
_CXX = ['cxa_thread_atexit_test', 'cxa_thread_atexit_nothr_test']
_CASES = {'free_sized_test': ['sized_deallocation'], 'bsearch_test': ['bsearch_test', 'bsearch_duplicates'], 'bsearch_b_test': ['bsearch_b_test'], 'bsearch_s_test': ['bsearch_s_constraints', 'bsearch_s_nmemb_zero', 'bsearch_s_h', 'bsearch_s_test'], 'clearenv_test': ['clearenv__single_var_test', 'clearenv__multiple_vars_test', 'clearenv__recreated_vars_test', 'clearenv__system_var_test', 'clearenv__recreated_system_var_test', 'clearenv__double_clear_vars', 'clearenv__environ_null', 'clearenv__putenv_vars'], 'cxa_atexit_test': ['simple_cxa_atexit', 'late_cxa_atexit', 'late_cxa_atexit_ran'], 'dynthr_test': ['maintc'], 'getenv_r_test': ['getenv_r_ok', 'getenv_r_einval', 'getenv_r_enoent', 'getenv_r_erange'], 'heapsort_test': ['heapsort_test'], 'libc_exit_test': ['quick_exit', 'recursive_exit1', 'recursive_exit2'], 'mergesort_test': ['mergesort_test'], 'qsort_test': ['qsort_test'], 'qsort_b_test': ['qsort_b_test'], 'qsort_r_compat_test': ['qsort_r_compat_test'], 'qsort_r_test': ['qsort_r_test'], 'qsort_s_test': ['qsort_s_nmemb_lt_zero', 'qsort_s_nmemb_gt_rmax', 'qsort_s_size_lt_zero', 'qsort_s_size_gt_rmax', 'qsort_s_null_compar', 'qsort_s_nmemb_lt_zero_h', 'qsort_s_nmemb_gt_rmax_h', 'qsort_s_size_lt_zero_h', 'qsort_s_size_gt_rmax_h', 'qsort_s_null_compar_h', 'qsort_s_h', 'qsort_s_test'], 'qsort_bench': ['qsort_bench'], 'set_constraint_handler_s_test': ['null_handler', 'abort_handler', 'ignore_handler'], 'strfmon_test': ['strfmon_locale_thousands', 'strfmon_examples', 'strfmon_cs_precedes_0', 'strfmon_cs_precedes_1', 'strfmon_international_currency_code', 'strfmon_plus_or_parenthesis', 'strfmon_l'], 'strfrom_test': ['strfromd_f', 'strfromd_e', 'strfromd_g', 'strfromd_a', 'strfromd_special', 'strfromd_truncation', 'strfromf_f', 'strfromf_e', 'strfromf_g', 'strfromf_a', 'strfromf_special', 'strfromf_truncation', 'strfroml_f', 'strfroml_e', 'strfroml_g', 'strfroml_a', 'strfroml_special', 'strfroml_truncation', 'strfrom_locale', 'strfrom_empty_format', 'strfrom_bad_specifier', 'strfrom_bad_format_truncation', 'strfrom_errno_preserved'], 'system_test': ['system_true', 'system_false', 'system_touch', 'system_null', 'system_concurrent'], 'tsearch_test': ['tsearch_test', 'tdestroy_test'], 'abs_test': ['abs_basic', 'imaxabs_basic', 'labs_basic', 'llabs_basic'], 'atoi_test': ['atof_strtod', 'atoi_strtol', 'atol_strtol', 'atoll_strtoll'], 'div_test': ['div_basic', 'ldiv_basic', 'lldiv_basic'], 'getenv_test': ['clearenv_basic', 'getenv_basic', 'putenv_basic', 'setenv_basic', 'setenv_mixed'], 'exit_test': ['exit_atexit', 'exit_basic', 'exit_status', 'exit_tmpfile'], 'hsearch_test': ['hsearch_basic', 'hsearch_duplicate', 'hsearch_nonexistent', 'hsearch_two'], 'posix_memalign_test': ['posix_memalign_basic', 'aligned_alloc_basic'], 'random_test': ['random_same'], 'strtod_test': ['strtod_basic', 'strtod_hex', 'strtod_inf', 'strtof_inf', 'strtold_inf', 'strtod_nan', 'strtof_nan', 'strtold_nan', 'strtod_round', 'strtod_underflow', 'strtod_gherman_bug'], 'strtol_test': ['strtol_base', 'strtol_case', 'strtol_range', 'strtol_signed'], 'cxa_thread_atexit_test': ['cxx__thr', 'cxx__thread_local_before', 'cxx__thread_local_after', 'cxx__thread_local_add_while_calling_dtors', 'cxx__thread_inf_dtors'], 'cxa_thread_atexit_nothr_test': ['cxx__nothr', 'cxx__thread_local_main', 'cxx__thread_inf_dtors']}
_CXX_RUNTIME = ["//lib/atf/libatf-c++:atf_cxx_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libgcc_s:gcc_s_shared"]
# These cases require a privileged chroot, absolute-path shell execution or
# a deliberately expensive benchmark. Keep them explicit.
_DEFERRED = {"system_test": True, "qsort_bench": True}
_TIMEOUTS = {"dynthr_test": {"maintc": 3}, "getenv_test": {"setenv_basic": 600}}
_MONETARY = ["de_DE.UTF-8", "en_GB.UTF-8", "en_US.UTF-8", "sv_SE.UTF-8"]
_NUMERIC = ["de_DE.UTF-8"]

def _locale_label(category, locale, catalog, aliases):
    mapping = {alias: source for source, alias in aliases}
    canonical = locale if locale in catalog else mapping.get(locale)
    if canonical not in catalog:
        fail("stdlib test requires missing maintained " + category + " locale: " + locale)
    return "//share/" + category + "_unicode:" + canonical


def stdlib_tests():
    for locale in _MONETARY:
        native.alias(name = "monetary_" + locale, actual = _locale_label("monetdef", locale, MONETARY, MONETARY_ALIASES))
    for locale in _NUMERIC:
        native.alias(name = "numeric_" + locale, actual = _locale_label("numericdef", locale, NUMERIC, NUMERIC_ALIASES))
    for name, library, headers in [
        ("atf", "//lib/atf/libatf-c:atf_c_shared", ["//contrib/atf:c_headers"]),
        ("atf_cxx", "//lib/atf/libatf-c++:atf_cxx_shared", ["//contrib/atf:cxx_headers"]),
        ("cxx", "//lib/libc++:cxx_shared", ["//contrib/llvm-project/libcxx/include:headers"]),
        ("cxxrt", "//lib/libcxxrt:cxxrt_shared", []),
        ("m", "//lib/msun:m_shared", []), ("gcc_s", "//lib/libgcc_s:gcc_s_shared", []),
        ("thr", "//lib/libthr:thr_shared", []), ("blocks", "//lib/libblocksruntime:blocks_shared", []),
        ("util", "//lib/libutil:util_shared", ["//lib/libutil:headers"]),
    ]:
        cc_import(name = name + "_interface", shared_library = library, deps = headers)
    cc_library(name = "test_headers", hdrs = ["test-search.h", "test-sort.h"], includes = ["."])
    entries = []
    for name, source, cxx in [("dynthr_mod", "dynthr_mod/dynthr_mod.c", False), ("libatexit", "libatexit/libatexit.cc", True)]:
        # The original C++ driver adds gcc_s with --as-needed; this plugin
        # resolves its ABI through libcxxrt and has no direct gcc_s requirement.
        deps = ([":cxx_interface", ":cxxrt_interface", ":m_interface", "//lib/libcompiler_rt:compiler_rt"] if cxx else [":thr_interface"]) + ["//lib/libc:shared_abi_interface"]
        cc_library(name = name + "_objects", srcs = ["//lib/libc/tests/stdlib/" + source.split("/")[0] + ":" + source.split("/")[1]],
            deps = deps,
            copts = [flag for flag in (libc_test_cxx_copts(6) if cxx else libc_test_copts(6)) if flag != "-fPIE"],
            features = ["bsd_small_pic"], linkstatic = True, target_compatible_with = _PLATFORM)
        cc_shared_library(name = name + "_shared", deps = [":" + name + "_objects"], shared_lib_name = name + ".so",
            user_link_flags = ["-nodefaultlibs", "-Wl,-soname," + name + ".so", "-Wl,--fatal-warnings,--warn-shared-textrel"],
            target_compatible_with = _PLATFORM)
        bsd_debug_split(name = name + "_debug", src = ":" + name + "_shared", binary_name = "install/" + name + ".so", debug_name = "install/" + name + ".so.debug",
            objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
        native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
        for kind, source_label, directory, tags in [
            ("shared", ":" + name + "_debug", _DIRECTORY, ["package=tests"]),
            ("symbols", ":" + name + "_symbols", "/usr/lib/debug" + _DIRECTORY, ["package=tests", "dbg"]),
        ]:
            target = name + "_" + kind + "_entry"
            bsd_install_file(name = target, src = source_label, destination = directory + "/" + name + ".so" + (".debug" if kind == "symbols" else ""),
                owner = "root", group = "wheel", mode = "0444", install_tags = tags)
            entries.append(":" + target)
    manifests = []
    tests = []
    deferred = []
    programs = {p: p + ".c" for p in _LOCAL}
    programs.update({p: _SOURCE + "t_" + p[:-5] + ".c" for p in _IMPORTED})
    programs.update({p: p + ".cc" for p in _CXX})
    programs.update({p: _SOURCE + p + ".c" for p in ["h_getopt", "h_getopt_long"]})
    for program, source in programs.items():
        cxx = program in _CXX
        atf = program in _CASES
        imported = program in _IMPORTED or program in ["h_getopt", "h_getopt_long"]
        blocks = program in ["bsearch_b_test", "qsort_b_test"]
        deps = ([":atf_cxx_interface"] if cxx else []) + ([":atf_interface"] if atf else [])
        if program in ["bsearch_test", "bsearch_b_test", "bsearch_s_test", "heapsort_test", "mergesort_test", "qsort_test", "qsort_b_test", "qsort_r_compat_test", "qsort_r_test", "qsort_s_test"]:
            deps.append(":test_headers")
        if imported:
            deps += ["//lib/libnetbsd:netbsd_pie", "//contrib/netbsd-tests:test_headers"]
        if program in ["h_getopt", "h_getopt_long"]:
            deps.append(":util_interface")
        if program in ["cxa_thread_atexit_test", "libc_exit_test", "system_test"]:
            deps.append(":thr_interface")
        if program == "strtod_test":
            deps.append(":m_interface")
        if blocks:
            deps.append(":blocks_interface")
        if cxx:
            deps += [":cxx_interface", ":cxxrt_interface", ":m_interface", "//lib/libcompiler_rt:compiler_rt", ":gcc_s_interface"]
        deps.append("//lib/libc:shared_abi_interface")
        bsd_link_sequence(name = program + "_link", deps = deps)
        copts = libc_test_cxx_copts() if cxx else libc_test_copts()
        if program == "free_sized_test":
            copts = [flag for flag in copts if flag != "-std=gnu17"] + ["-std=c2x"]
        if blocks:
            copts.append("-fblocks")
        cc_binary(name = program, srcs = [source], deps = [":" + program + "_link"], copts = copts,
            defines = ["__HAVE_FENV", "__HAVE_LONG_DOUBLE"] + ([] if cxx else ["PIC"]),
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = program + "_install", program = program, manual = None, package = "tests", bindir = _DIRECTORY)
        manifests.append(":" + program + "_install")
        for case in _CASES.get(program, []):
            name = program + "_" + case + "_runtime"
            pending = program in _DEFERRED
            timeout = _TIMEOUTS.get(program, {}).get(case, 0)
            bsd_atf_test(name = name, body = ":" + program, case_name = case, interface = "program",
                data_paths = ({":dynthr_mod_shared": "dynthr_mod.so"} if program == "dynthr_test" else ({":libatexit_shared": "libatexit.so"} if program == "cxa_atexit_test" else {})),
                locale_files = ({":monetary_" + locale: locale + "/LC_MONETARY" for locale in _MONETARY} if program == "strfmon_test" else ({":numeric_" + locale: locale + "/LC_NUMERIC" for locale in _NUMERIC} if program == "strfrom_test" else {})),
                runtime_lib = LIBC_TEST_RUNTIME + (_CXX_RUNTIME if cxx else (_CXX_RUNTIME[1:] if program == "cxa_atexit_test" else [])) +
                    (["//lib/libthr:thr_shared"] if program in ["cxa_thread_atexit_test", "libc_exit_test", "system_test", "dynthr_test"] else []) +
                    (["//lib/libblocksruntime:blocks_shared"] if blocks else []) + (["//lib/msun:m_shared"] if program == "strtod_test" else []),
                test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
                tags = ["manual", "external", "no-remote"] if pending else [],
                required_user = "root" if program == "system_test" and case == "system_null" else "",
                body_timeout_seconds = timeout,
                target_compatible_with = _PLATFORM, size = "large" if program == "qsort_bench" or timeout >= 600 else "small")
            (deferred if pending else tests).append(":" + name)
    bsd_script_wrapper(name = "getopt_test", body = _SOURCE + "t_getopt.sh", interpreter = "/usr/libexec/atf-sh",
        cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_install_file(name = "shell_entry", src = ":getopt_test", destination = _DIRECTORY + "/getopt_test",
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
    entries.append(":shell_entry")
    for case in ["getopt", "getopt_long"]:
        name = "getopt_" + case + "_runtime"
        bsd_atf_test(name = name, body = _SOURCE + "t_getopt.sh", case_name = case,
            subr = "//libexec/atf/atf-sh:shell_library",
            data_paths = {":h_getopt": "h_getopt", ":h_getopt_long": "h_getopt_long"},
            runtime_bin = ["//bin/sh:sh", "//bin/cat:cat", "//bin/rm:rm", "//usr.bin/dirname:dirname", "//libexec/atf/atf-sh:atf-sh", "//libexec/atf/atf-check:atf-check"],
            runtime_lib = LIBC_TEST_RUNTIME + _CXX_RUNTIME + ["//lib/libutil:util_shared"],
            test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
            target_compatible_with = _PLATFORM, size = "small")
        tests.append(":" + name)
    names = sorted(_CASES.keys() + ["getopt_test"])
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = names, interfaces = {p: "atf" for p in names})
    bsd_install_file(name = "kyuafile_entry", src = ":kyuafile", destination = _DIRECTORY + "/Kyuafile",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    bsd_install_manifest(name = "install_manifest", manifests = manifests, entries = entries + [":kyuafile_entry"], visibility = ["//visibility:public"])
    bsd_test_install_archive(name = "install_archive", directory = _DIRECTORY, manifests = [":install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], visibility = ["//visibility:public"], target_compatible_with = _PLATFORM)
    native.test_suite(name = "runtime_tests", tests = tests)
    native.test_suite(name = "deferred_runtime_tests", tests = deferred, tags = ["manual"])
    native.alias(name = "free_sized_runtime_program", actual = ":free_sized_test")
    native.alias(name = "native_sized_deallocation", actual = ":free_sized_test_sized_deallocation_runtime", visibility = ["//visibility:public"])
