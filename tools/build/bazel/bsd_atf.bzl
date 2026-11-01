# SPDX-License-Identifier: BSD-2-Clause
"""Native ATF shell/program test adapter for the Bazel test protocol."""
def _atf_test(ctx):
    if ctx.attr.body_timeout_seconds < 0 or ctx.attr.cleanup_timeout_seconds < 0:
        fail("ATF phase deadlines must be nonnegative seconds")
    links = {}
    environment = {
        "BSD_ATF_BODY_TIMEOUT": str(ctx.attr.body_timeout_seconds),
        "BSD_ATF_CLEANUP_TIMEOUT": str(ctx.attr.cleanup_timeout_seconds),
        "BSD_ATF_CASE": ctx.attr.case_name,
        "BSD_ATF_CLEANUP": "1" if ctx.attr.cleanup else "0",
        "BSD_ATF_REQUIRED_USER": ctx.attr.required_user,
        "BSD_ATF_INTERFACE": ctx.attr.interface,
        "BSD_ATF_HARNESS": ctx.file.body.basename,
        "BSD_ATF_CONFIG_COUNT": str(len(ctx.attr.config_files)),
    }
    if ctx.file.loader:
        if ctx.attr.interface != "program":
            fail("explicit ATF loader requires the program interface")
        links["atf-loader/loader"] = ctx.file.loader
    environment["BSD_ATF_LOADER"] = "1" if ctx.file.loader else "0"
    names = []
    for target, name in ctx.attr.config_files.items():
        if not name or name in names or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in name.elems()]):
            fail("ATF configuration names must be unique identifiers")
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1:
            fail("ATF configuration path requires one declared file")
        index = str(len(names))
        # Keep executable identity (for argv[0]/shell prompts) while isolating
        # configuration entries that may use the same basename.
        path = "atf-config/" + index + "/" + files[0].basename
        links[path] = files[0]
        environment["BSD_ATF_CONFIG_NAME_" + index] = name
        environment["BSD_ATF_CONFIG_PATH_" + index] = path
        names.append(name)
    for file in ctx.files.runtime_bin:
        key = "atf-runtime/bin/" + file.basename
        if key in links:
            fail("duplicate runtime tool: " + key)
        links[key] = file
    for file in ctx.files.runtime_lib:
        key = "atf-runtime/lib/" + file.basename
        if key in links:
            fail("duplicate runtime library: " + key)
        links[key] = file
    for target, destination in ctx.attr.locale_files.items():
        parts = destination.split("/")
        if len(parts) != 2 or parts[0] in ["", ".", ".."] or parts[1] not in ["LC_CTYPE", "LC_COLLATE", "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME"]:
            fail("locale destination must be locale-name/LC_category")
        files = target[DefaultInfo].files.to_list()
        key = "atf-runtime/locale/" + destination
        if len(files) != 1 or key in links:
            fail("locale entry requires one file and a unique destination")
        links[key] = files[0]
    if ctx.attr.interface == "shell" and not ctx.file.subr:
        fail("shell ATF tests require their declared shell library")
    if ctx.file.subr:
        links["atf-runtime/share/libatf-sh.subr"] = ctx.file.subr
    links["atf-suite/" + ctx.file.body.basename] = ctx.file.body
    for file in ctx.files.data:
        key = "atf-suite/" + file.basename
        if key in links:
            fail("duplicate test fixture: " + key)
        links[key] = file
    for target, destination in ctx.attr.data_paths.items():
        parts = destination.split("/")
        files = target[DefaultInfo].files.to_list()
        if destination.startswith("/") or any([part in ["", ".", ".."] for part in parts]):
            fail("fixture destination must be a normalized relative path")
        key = "atf-suite/" + destination
        if len(files) != 1 or any([key == existing or key.startswith(existing + "/") or existing.startswith(key + "/") for existing in links]):
            fail("mapped fixture requires one file and a unique nonconflicting destination")
        links[key] = files[0]
    ctx.actions.symlink(output = ctx.outputs.executable,
                        target_file = ctx.executable.runner, is_executable = True)
    runfiles = ctx.runfiles(files = [ctx.executable.runner], symlinks = links)
    targets = [ctx.attr.runner, ctx.attr.body] + ctx.attr.runtime_bin + ctx.attr.runtime_lib + ctx.attr.config_files.keys() + ctx.attr.locale_files.keys() + ctx.attr.data + ctx.attr.data_paths.keys()
    if ctx.attr.loader:
        targets.append(ctx.attr.loader)
    runfiles = runfiles.merge_all([target[DefaultInfo].default_runfiles for target in targets])
    return [DefaultInfo(executable = ctx.outputs.executable, runfiles = runfiles),
            RunEnvironmentInfo(environment = environment)]

bsd_atf_test = rule(
    implementation = _atf_test,
    test = True,
    attrs = {
        "case_name": attr.string(mandatory = True),
        "cleanup": attr.bool(default = False),
        "required_user": attr.string(default = "", values = ["", "root", "unprivileged"],
            doc = "Precondition checked by the runner before executing any test body."),
        "body_timeout_seconds": attr.int(default = 0, doc = "ATF body deadline; zero uses only the outer Bazel timeout."),
        "cleanup_timeout_seconds": attr.int(default = 300, doc = "Separate cleanup deadline, matching Kyua default."),
        "config_files": attr.label_keyed_string_dict(allow_files = True),
        "body": attr.label(allow_single_file = True, mandatory = True),
        "subr": attr.label(allow_single_file = True),
        "interface": attr.string(default = "shell", values = ["shell", "program"]),
        "data": attr.label_list(allow_files = True),
        "data_paths": attr.label_keyed_string_dict(allow_files = True, doc = "Declared fixture files mapped to relative suite paths."),
        "runtime_bin": attr.label_list(allow_files = True),
        "runtime_lib": attr.label_list(allow_files = True),
        "loader": attr.label(allow_single_file = True, doc = "Optional declared ELF loader for the ATF program body and cleanup; does not redirect child execs."),
        "locale_files": attr.label_keyed_string_dict(allow_files = True),
        "runner": attr.label(executable = True, cfg = "exec", mandatory = True),
    },
)
