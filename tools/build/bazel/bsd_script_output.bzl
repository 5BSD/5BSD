# SPDX-License-Identifier: BSD-2-Clause
"""Run a maintained shell generator with an explicit tool-only PATH."""
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")

def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"

def _generate(ctx):
    if ctx.files.additional_sources and ctx.attr.input_mode != "argument":
        fail("additional sources require argument input mode")
    directory = None
    if ctx.attr.input_mode == "directory":
        anchor = ctx.attr.directory_anchor
        if not anchor or any([part in ["", ".", ".."] for part in anchor.split("/")]):
            fail("directory_anchor must be a normalized relative file path")
        suffix = "/" + anchor
        if not ctx.file.src.path.endswith(suffix):
            fail("directory anchor does not match the declared source path")
        directory = ctx.file.src.path[:-len(suffix)]
    elif ctx.attr.directory_anchor:
        fail("directory_anchor requires directory input mode")
    output = ctx.actions.declare_file(ctx.attr.output)
    aliases = []
    tools = [ctx.attr.shell[DefaultInfo].files_to_run]
    names = []
    for target, name in ctx.attr.path_tools.items():
        if not name or "/" in name or name in [".", ".."] or name in names:
            fail("unique tool basenames required")
        names.append(name)
        executable = target[DefaultInfo].files_to_run
        files = target[DefaultInfo].files.to_list()
        tool_file = executable.executable
        if not tool_file:
            if len(files) != 1:
                fail("PATH tool must provide one executable file: " + str(target.label))
            tool_file = files[0]
        alias = ctx.actions.declare_file(ctx.label.name + ".tools/" + name)
        ctx.actions.symlink(output = alias, target_file = tool_file, is_executable = True)
        aliases.append(alias)
        tools.append(executable if executable.executable else tool_file)
    if not aliases:
        fail("explicit generator PATH tools required")
    args = (["--stdin", ctx.file.src.path] if ctx.attr.input_mode == "stdin" else [])
    args += [output.path, ctx.executable.shell.path, ctx.file.script.path]
    args += ctx.attr.arguments
    if ctx.attr.input_mode == "argument":
        args.append(ctx.file.src.path)
        args += [file.path for file in ctx.files.additional_sources]
    if directory != None:
        args.append(directory)
    environment = dict(ctx.attr.environment)
    for key in environment:
        if key in ["LC_ALL", "PATH", "CPP", "LD_LIBRARY_PATH"]:
            fail("generator environment cannot override " + key)
    environment.update({"LC_ALL": "C", "PATH": aliases[0].dirname})
    compiler_inputs = []
    generated_inputs = []
    if ctx.attr.use_cpp:
        toolchain = find_cc_toolchain(ctx)
        features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
            requested_features = ctx.features, unsupported_features = ctx.disabled_features)
        context = cc_common.merge_cc_infos(cc_infos = [dep[CcInfo] for dep in ctx.attr.cpp_deps]).compilation_context
        variables = cc_common.create_compile_variables(cc_toolchain = toolchain,
            feature_configuration = features, user_compile_flags = ctx.attr.cpp_flags,
            include_directories = context.includes,
            quote_include_directories = context.quote_includes,
            system_include_directories = context.system_includes,
            framework_include_directories = context.framework_includes,
            preprocessor_defines = context.defines)
        command = [cc_common.get_tool_for_action(feature_configuration = features,
            action_name = ACTION_NAMES.c_compile)]
        command += cc_common.get_memory_inefficient_command_line(feature_configuration = features,
            action_name = ACTION_NAMES.c_compile, variables = variables)
        command += ["-E"]
        wrapper = ctx.actions.declare_file(ctx.label.name + ".cpp.sh")
        ctx.actions.write(wrapper, "exec " + " ".join([_quote(v) for v in command]) + ' "$@"\n')
        # The maintained generators expand $CPP by shell word splitting.
        for path in [ctx.executable.shell.path, wrapper.path]:
            if any([c in path for c in [" ", "\t", "\n", "*", "?", "["]]):
                fail("CPP command paths cannot contain shell splitting or glob characters")
        environment["CPP"] = ctx.executable.shell.path + " " + wrapper.path
        if not ctx.attr.compiler_inputs:
            fail("use_cpp requires declared compiler_inputs")
        declared_compiler_inputs = ctx.attr.compiler_inputs[DefaultInfo].files
        if command[0] not in [file.path for file in declared_compiler_inputs.to_list()]:
            fail("compiler_inputs must contain the selected C toolchain compiler")
        compiler_inputs = [declared_compiler_inputs, context.headers]
        generated_inputs = [wrapper]
    elif ctx.attr.cpp_flags or ctx.attr.compiler_inputs or ctx.attr.cpp_deps:
        fail("cpp_flags, cpp_deps and compiler_inputs require use_cpp")
    # A generator may cd while discovering declared inputs. Resolve the tool
    # search directory against the action execroot before entering its script.
    launcher = ctx.actions.declare_file(ctx.label.name + ".launch.sh")
    library_dirs = []
    for library in ctx.files.runtime_libraries:
        if library.dirname not in library_dirs:
            library_dirs.append(library.dirname)
    runtime_environment = ""
    if library_dirs:
        runtime_environment = 'LD_LIBRARY_PATH=' + ":".join(['"$(pwd -P)/"' + _quote(directory) for directory in library_dirs]) + '\nexport LD_LIBRARY_PATH\n'
    ctx.actions.write(launcher, runtime_environment + 'PATH="$(pwd -P)/$PATH"\nexport PATH\nexec ' +
        _quote(ctx.executable.shell.path) + " " + _quote(ctx.file.script.path) + ' "$@"\n')
    args[args.index(ctx.file.script.path)] = launcher.path
    generated_inputs.append(launcher)
    ctx.actions.run(executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = args, inputs = depset([ctx.file.script, ctx.file.src] + aliases + ctx.files.inputs + ctx.files.additional_sources + generated_inputs + ctx.files.runtime_libraries, transitive = compiler_inputs),
        tools = tools + ctx.files.runtime, outputs = [output],
        env = environment, use_default_shell_env = False,
        mnemonic = "BSDScriptOutput")
    return [DefaultInfo(files = depset([output]))]
bsd_script_output = rule(implementation = _generate, attrs = {
    "script": attr.label(allow_single_file = True, mandatory = True),
    "src": attr.label(allow_single_file = True, mandatory = True),
    "inputs": attr.label_list(allow_files = True),
    "additional_sources": attr.label_list(allow_files = True),
    "output": attr.string(mandatory = True),
    "input_mode": attr.string(default = "stdin", values = ["stdin", "argument", "directory"]),
    "directory_anchor": attr.string(doc = "Source path relative to the directory argument; all other accessed files must be declared in inputs."),
    "environment": attr.string_dict(),
    "use_cpp": attr.bool(default = False),
    "cpp_flags": attr.string_list(),
    "cpp_deps": attr.label_list(providers = [CcInfo], doc = "Target compilation contexts supplying declared preprocessing headers, includes and defines."),
    "compiler_inputs": attr.label(doc = "Declared selected compiler, headers, resource files and runtime closure."),
    "arguments": attr.string_list(),
    "path_tools": attr.label_keyed_string_dict(cfg = "exec", allow_files = True, mandatory = True),
    "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
}, fragments = ["cpp"], toolchains = use_cc_toolchain())
