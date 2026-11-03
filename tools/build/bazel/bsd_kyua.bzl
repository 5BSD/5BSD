# SPDX-License-Identifier: BSD-2-Clause
"""Run declared TAP/ATF programs through Kyua, with optional native loader checks."""

load(":bsd_kyua_metadata.bzl", "kyua_metadata_fields")

def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"

def _copy_suite_file(ctx, source, output):
    if not ctx.executable.python or not ctx.file.python_home:
        fail("suite file staging requires a declared Python tool")
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-c", "import os,shutil,sys; shutil.copyfile(sys.argv[1],sys.argv[2]); os.chmod(sys.argv[2],0o755)", source.path, output.path],
        inputs = depset([source, ctx.file.python_home] + ctx.files.runtime),
        outputs = [output],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        mnemonic = "BSDTestSuiteFile",
    )

def _impl(ctx):
    program_path = ctx.attr.program_path or ctx.executable.program.basename
    if program_path.startswith("/") or any([part in ["", ".", ".."] for part in program_path.split("/")]):
        fail("program_path must be a normalized relative path")
    program_directory = program_path.rsplit("/", 1)[0] + "/" if "/" in program_path else ""
    program = ctx.actions.declare_file(ctx.label.name + ".suite/" + program_path)
    if ctx.attr.runtime_libraries:
        if not ctx.executable.python or not ctx.file.python_home:
            fail("native suite staging requires an explicit Python execution tool")
        # FreeBSD derives $ORIGIN from the executable's resolved path. A symlink
        # back to its component would bypass the suite's declared SONAME files.
        _copy_suite_file(ctx, ctx.executable.program, program)
    else:
        ctx.actions.symlink(output = program, target_file = ctx.executable.program, is_executable = True)
    kyuafile = ctx.actions.declare_file(ctx.label.name + ".suite/Kyuafile")
    if ctx.attr.case_timeout < 0:
        fail("Kyua timeout cannot be negative")
    properties = ["name=" + json.encode(program.basename)]
    if ctx.attr.case_timeout:
        properties.append("timeout=" + str(ctx.attr.case_timeout))
    properties += kyua_metadata_fields(ctx.attr.test_metadata,
                                      reserved = ["timeout"] if ctx.attr.case_timeout else [])
    program_kyuafile = kyuafile
    if program_directory:
        program_kyuafile = ctx.actions.declare_file(ctx.label.name + ".suite/" + program_directory + "Kyuafile")
        ctx.actions.write(kyuafile, "syntax(2)\ninclude(" + json.encode(program_directory + "Kyuafile") + ")\n")
    ctx.actions.write(program_kyuafile, "syntax(2)\ntest_suite(" + json.encode(ctx.attr.suite) + ")\n" + ctx.attr.interface + "_test_program{" + ", ".join(properties) + "}\n")
    files = [program, kyuafile, program_kyuafile, ctx.executable.program, ctx.executable.kyua] + ctx.files.runtime
    suite_paths = {}
    artifact_files = {}
    occupied = {program_path: True, "Kyuafile": True}
    occupied[program_directory + "Kyuafile"] = True
    for soname in ctx.attr.runtime_libraries.values():
        occupied[program_directory + soname] = True
    for target, name in ctx.attr.suite_files.items():
        parts = name.split("/")
        if not name or any([part in ["", ".", ".."] for part in parts]):
            fail("suite files require normalized relative paths without traversal")
        for existing in occupied:
            if name == existing or name.startswith(existing + "/") or existing.startswith(name + "/"):
                fail("suite file paths must be unique and cannot overlap files")
        occupied[name] = True
        artifacts = target[DefaultInfo].files.to_list()
        if len(artifacts) != 1:
            fail("one declared artifact per suite file required")
        artifact = artifacts[0]
        staged = ctx.actions.declare_file(ctx.label.name + ".suite/" + name)
        _copy_suite_file(ctx, artifact, staged)
        files += [staged, artifact]
        suite_paths[name] = staged
        artifact_files[name] = staged
    commands = ["#!/bin/sh", "set -eu", 'root="$TEST_SRCDIR/$TEST_WORKSPACE"']
    path_entries = []
    path_names = {}
    for target, name in ctx.attr.path_programs.items():
        if not name or name in [".", ".."] or "/" in name or name in path_names:
            fail("PATH program names must be unique basenames")
        executable = target[DefaultInfo].files_to_run.executable
        if not executable:
            fail("PATH programs must provide an executable")
        path_names[name] = True
        staged = ctx.actions.declare_file(ctx.label.name + ".bin/" + name)
        ctx.actions.symlink(output = staged, target_file = executable, is_executable = True)
        files += [staged, executable]
        path_entries.append(staged)
        # Refuse missing/nonexecutable candidates before Kyua can skip a test
        # or a shell can resolve a same-named host program.
        commands.append('test -x "$root/"' + _quote(staged.short_path))
    if ctx.attr.runtime_libraries:
        if not ctx.executable.python or not ctx.file.python_home or not ctx.file.runtime_checker:
            fail("native runtime checks require an explicit Python tool and checker")
        check = ('PYTHONPATH= PYTHONNOUSERSITE=1 PYTHONHOME="$root/"' + _quote(ctx.file.python_home.short_path[:-len(ctx.file.python_home.basename)]) + ' "$root/"' + _quote(ctx.executable.python.short_path) + ' -B "$root/"' +
                 _quote(ctx.file.runtime_checker.short_path) + ' --binary "$root/"' +
                 _quote(program.short_path) + ' --output "$TEST_UNDECLARED_OUTPUTS_DIR/runtime"' +
                 (' --argument=-l' if ctx.attr.interface == "atf" else ' --trace-only'))
        files += [ctx.executable.python, ctx.file.python_home, ctx.file.runtime_checker]
        sonames = {}
        for target, soname in ctx.attr.runtime_libraries.items():
            if not soname or "/" in soname or soname in [".", ".."] or soname in sonames:
                fail("unique runtime SONAME basenames required")
            sonames[soname] = True
            artifacts = target[DefaultInfo].files.to_list()
            if len(artifacts) != 1:
                fail("one declared runtime library artifact required")
            artifact = artifacts[0]
            link = ctx.actions.declare_file(ctx.label.name + ".suite/" + program_directory + soname)
            ctx.actions.symlink(output = link, target_file = artifact)
            files += [link, artifact]
            artifact_files[soname] = artifact
            check += ' --library ' + _quote(soname + '=') + '"$root/"' + _quote(artifact.short_path)
        commands.append(check)
    for module, libraries in ctx.attr.module_dependencies.items():
        if module not in suite_paths or not libraries or not ctx.attr.runtime_libraries:
            fail("module loader check requires a staged module and declared libraries")
        check = ('PYTHONPATH= PYTHONNOUSERSITE=1 PYTHONHOME="$root/"' + _quote(ctx.file.python_home.short_path[:-len(ctx.file.python_home.basename)]) + ' "$root/"' + _quote(ctx.executable.python.short_path) + ' -B "$root/"' +
                 _quote(ctx.file.runtime_checker.short_path) + ' --trace-only --binary "$root/"' +
                 _quote(suite_paths[module].short_path) + ' --output "$TEST_UNDECLARED_OUTPUTS_DIR/"' + _quote('module-runtime-' + module))
        for soname in libraries:
            if soname not in artifact_files:
                fail("module dependency lacks a declared suite artifact")
            check += ' --library ' + _quote(soname + '=') + '"$root/"' + _quote(artifact_files[soname].short_path)
        commands.append(check)
    # Host /bin/sh, env, ldd and Kyua/Python execution runtimes remain explicit
    # qualification limits; this adapter does not claim hermetic execution.
    prefix = ''
    if ctx.attr.clean_environment:
        prefix += '/usr/bin/env -i PATH=/bin:/usr/bin LC_ALL=C TMPDIR="$TEST_TMPDIR" PWD="$(pwd -P)" '
        for key, value in ctx.attr.test_environment.items():
            prefix += _quote(key + '=' + value) + ' '
    if path_entries:
        if "PATH" in ctx.attr.test_environment:
            fail("test_environment PATH conflicts with declared PATH programs")
        # Ancillary host tools remain explicit runtime limits of this adapter.
        # Candidate names are pinned ahead of that fixed ancillary search path.
        prefix += '/usr/bin/env PATH="$root/"' + _quote(path_entries[0].short_path.rsplit("/", 1)[0]) + ':/bin:/usr/bin '
    if ctx.attr.case_name and any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for c in ctx.attr.case_name.elems()]):
        fail("Kyua case_name must be an ATF identifier")
    kyua_command = prefix + '\"$root/\"' + _quote(ctx.executable.kyua.short_path) + ' -c none'
    config_arguments = ""
    config_names = {}
    if ctx.attr.config_values or ctx.attr.config_files:
        if not ctx.attr.suite or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for c in ctx.attr.suite.elems()]):
            fail("configured Kyua suite must be an identifier")
    for name, value in ctx.attr.config_values.items():
        if not name or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for c in name.elems()]):
            fail("Kyua configuration names must be identifiers")
        config_names[name] = True
        config_arguments += " -v " + _quote("test_suites." + ctx.attr.suite + "." + name + "=" + value)
    for target, name in ctx.attr.config_files.items():
        if not name or name in config_names or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for c in name.elems()]):
            fail("Kyua configuration names must be unique identifiers")
        config_names[name] = True
        artifacts = target[DefaultInfo].files.to_list()
        if len(artifacts) != 1:
            fail("Kyua configuration file requires one declared artifact")
        files.append(artifacts[0])
        config_arguments += " -v " + _quote("test_suites." + ctx.attr.suite + "." + name + "=") + '\"$root/\"' + _quote(artifacts[0].short_path)
    suite_argument = '"$root/"' + _quote(kyuafile.short_path)
    if ctx.attr.materialize_suite:
        if not ctx.executable.python or not ctx.file.python_home:
            fail("suite materialization requires declared Python")
        # Bazel runfiles can be symlinks. Preserve tests of O_NOFOLLOW loaders
        # by copying only the declared suite into the private test directory.
        commands.append('PYTHONPATH= PYTHONNOUSERSITE=1 PYTHONHOME="$root/"' + _quote(ctx.file.python_home.short_path[:-len(ctx.file.python_home.basename)]) +
                        ' "$root/"' + _quote(ctx.executable.python.short_path) + ' -B -c ' +
                        _quote('import shutil,sys; shutil.copytree(sys.argv[1],sys.argv[2],symlinks=False)') +
                        ' "$root/"' + _quote(kyuafile.short_path.rsplit("/", 1)[0]) + ' "$TEST_TMPDIR/materialized-suite"')
        suite_argument = '"$TEST_TMPDIR/materialized-suite/Kyuafile"'
    commands.append("status=0")
    commands.append(kyua_command + config_arguments + ' --logfile="$TEST_UNDECLARED_OUTPUTS_DIR/kyua.log" test' +
                    ' --kyuafile=' + suite_argument +
                    ' --results-file="$TEST_UNDECLARED_OUTPUTS_DIR/results.db"' +
                    (' ' + _quote(program_path + ":" + ctx.attr.case_name) if ctx.attr.case_name else '') +
                    ' || status=$?')
    # Preserve Kyua JUnit output, including skips and failed runs.
    # Reconcile expected failures from typed database results below.
    # Report generation failure must also fail the test rather than hide results.
    commands.append(kyua_command + ' --logfile="$TEST_UNDECLARED_OUTPUTS_DIR/kyua-report.log" report-junit' +
                    ' --results-file="$TEST_UNDECLARED_OUTPUTS_DIR/results.db" --output="$XML_OUTPUT_FILE"')
    files += [ctx.executable._report_python, ctx.file._report_python_home, ctx.file._reporter] + ctx.files._report_runtime
    commands.append('PYTHONPATH= PYTHONNOUSERSITE=1 PYTHONHOME="$root/"' + _quote(ctx.file._report_python_home.short_path[:-len(ctx.file._report_python_home.basename)]) +
                    ' "$root/"' + _quote(ctx.executable._report_python.short_path) + ' -B "$root/"' + _quote(ctx.file._reporter.short_path) +
                    ' --kyua="$root/"' + _quote(ctx.executable.kyua.short_path) + ' --database="$TEST_UNDECLARED_OUTPUTS_DIR/results.db" --report="$XML_OUTPUT_FILE" --program=' + _quote(program_path))
    commands.append('exit "$status"')
    runner = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(runner, "\n".join(commands) + "\n", is_executable = True)
    runfiles = ctx.runfiles(files = files)
    targets = [ctx.attr.program, ctx.attr.kyua, ctx.attr._report_python] + ctx.attr.runtime_libraries.keys() + ctx.attr.suite_files.keys() + ctx.attr.config_files.keys() + ctx.attr.path_programs.keys()
    if ctx.attr.python:
        targets.append(ctx.attr.python)
    runfiles = runfiles.merge_all([target[DefaultInfo].default_runfiles for target in targets])
    providers = [DefaultInfo(executable = runner, runfiles = runfiles)]
    if ctx.attr.test_environment and not ctx.attr.clean_environment:
        providers.append(RunEnvironmentInfo(environment = ctx.attr.test_environment))
    return providers

bsd_kyua_test = rule(
    implementation = _impl,
    test = True,
    attrs = {
        "_report_python": attr.label(default = "@bsd_sdk//toolchain:extra_python", allow_single_file = True, executable = True, cfg = "exec"),
        "_report_python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
        "_report_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], allow_files = True, cfg = "exec"),
        "_reporter": attr.label(default = "//tools/build/bazel:kyua_junit.py", allow_single_file = True),
        "interface": attr.string(default = "tap", values = ["tap", "atf"]),
        "program_path": attr.string(doc = "Normalized program path within the suite, preserving installed relative fixture layout."),
        "program": attr.label(executable = True, cfg = "target", mandatory = True),
        "kyua": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
        "case_timeout": attr.int(default = 60),
        "config_values": attr.string_dict(doc = "Explicit ATF configuration scalars scoped to this suite."),
        "config_files": attr.label_keyed_string_dict(allow_files = True, doc = "Declared artifact to ATF configuration name."),
        "case_name": attr.string(doc = "Optional individual ATF case; empty runs the program suite."),
        "python": attr.label(executable = True, allow_single_file = True, cfg = "exec"),
        "python_home": attr.label(allow_single_file = True, cfg = "exec"),
        "runtime_checker": attr.label(allow_single_file = True),
        "runtime_libraries": attr.label_keyed_string_dict(allow_files = True),
        "suite_files": attr.label_keyed_string_dict(allow_files = True),
        "materialize_suite": attr.bool(default = False, doc = "Copy declared suite files to private test storage for tests requiring regular files rather than runfile symlinks."),
        "path_programs": attr.label_keyed_string_dict(doc = "Declared target executables pinned ahead of ancillary /bin:/usr/bin tools."),
        "module_dependencies": attr.string_list_dict(),
        "clean_environment": attr.bool(default = False),
        "suite": attr.string(default = "bsd_bazel"),
        "test_metadata": attr.string(default = "{}"),
        "test_environment": attr.string_dict(),
    },
)

bsd_kyua_tap_test = bsd_kyua_test
