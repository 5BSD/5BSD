# SPDX-License-Identifier: BSD-2-Clause
"""Device-tree preprocessing and compilation with declared tools and inputs."""

def _directories(directories, files):
    for directory in directories:
        if not directory or any([part in ["", ".", ".."] for part in directory.split("/")]) or "\\" in directory:
            fail("include directory must be a normalized execution-root-relative path: " + directory)
        if not any([file.path.startswith(directory + "/") for file in files]):
            fail("include directory has no declared input: " + directory)

def _dtb(ctx):
    inputs = [ctx.file.src] + ctx.files.append_sources + ctx.files.textual_inputs
    _directories(ctx.attr.cpp_include_directories, inputs)
    _directories(ctx.attr.dtc_include_directories, inputs)
    empty = ctx.actions.declare_file(ctx.label.name + ".empty")
    preprocessed = ctx.actions.declare_file(ctx.label.name + ".preprocessed.dts")
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.write(empty, "")
    arguments = [preprocessed.path, ctx.executable.cpp.path, "-nostdinc", "-P", "-x", "assembler-with-cpp"] + ctx.attr.cpp_options
    for directory in ctx.attr.cpp_include_directories:
        arguments += ["-I", directory]
    for source in [ctx.file.src] + ctx.files.append_sources:
        arguments += ["-include", source.path]
    arguments.append(empty.path)
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = arguments,
        inputs = inputs + [empty],
        tools = [ctx.attr.cpp[DefaultInfo].files_to_run] + ctx.files.cpp_inputs,
        outputs = [preprocessed], env = {"LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDDeviceTreePreprocess",
    )
    arguments = ctx.attr.dtc_options + ["-O", "dtb", "-o", output.path]
    for directory in ctx.attr.dtc_include_directories:
        arguments += ["-i", directory]
    arguments.append(preprocessed.path)
    environment = {"LC_ALL": "C"}
    if ctx.files.runtime_libraries:
        environment["LD_LIBRARY_PATH"] = ":".join(sorted(depset([f.dirname for f in ctx.files.runtime_libraries]).to_list()))
    ctx.actions.run(
        executable = ctx.attr.dtc[DefaultInfo].files_to_run,
        arguments = arguments, inputs = [preprocessed] + inputs,
        tools = ctx.files.runtime_libraries, outputs = [output],
        env = environment, use_default_shell_env = False,
        mnemonic = "BSDDeviceTreeCompile",
    )
    return [DefaultInfo(files = depset([output])),
            OutputGroupInfo(preprocessed = depset([preprocessed]))]

bsd_dtb = rule(
    implementation = _dtb,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "append_sources": attr.label_list(allow_files = True),
        "textual_inputs": attr.label_list(allow_files = True),
        "cpp_include_directories": attr.string_list(),
        "dtc_include_directories": attr.string_list(),
        "cpp_options": attr.string_list(),
        "dtc_options": attr.string_list(),
        "output": attr.string(mandatory = True),
        "cpp": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
        "redirect": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
        "cpp_inputs": attr.label_list(allow_files = True, cfg = "exec"),
        "dtc": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
        "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
