# SPDX-License-Identifier: BSD-2-Clause
"""Architecture-aware declared firmware generation and native module composition."""
load(":amd64_generic_module.bzl", "amd64_generic_module", "amd64_generic_module_objects")
load(":cross_generic_module.bzl", "cross_generic_module", "cross_generic_module_objects")
load(":bsd_awk_output.bzl", "bsd_awk_output")
load(":bsd_object_alias.bzl", "bsd_object_alias")
load(":bsd_uudecode.bzl", "bsd_uudecode")


def _objects(arch, **kwargs):
    if arch == "amd64":
        amd64_generic_module_objects(**kwargs)
    else:
        cross_generic_module_objects(arch = arch, **kwargs)


def bsd_firmware_module(arch, module, images, license = "", export_all = False, package = "kernel", extra_objects = [], extra_object_order = []):
    """Images declare source, encoding (raw/uu), filename and original FIRMWS spec."""
    if arch not in ["amd64", "arm64", "riscv"]:
        fail("unsupported firmware target architecture")
    prefix = "" if arch == "amd64" else arch + "_"
    output_prefix = "" if arch == "amd64" else prefix + "firmware/"
    if not images:
        fail("firmware module requires declared images")
    filenames = []
    objects = []
    specs = []
    for index, image in enumerate(images):
        filename = image["filename"]
        spec = image["spec"]
        if not filename or any([c in filename for c in ["/", "\\", ":", "\n", "\r", "\t", " "]]) or filename in [".", ".."]:
            fail("firmware filename must be a basename")
        if filename in filenames or spec.split(":")[0] != filename:
            fail("duplicate filename or inconsistent firmware registration spec")
        filenames.append(filename)
        specs.append(spec)
        name = "firmware_%d" % index
        if image["encoding"] == "uu":
            bsd_uudecode(name = prefix + name, src = image["source"], output = output_prefix + filename,
                decoder = "//usr.bin/bintrans:bintrans", loader = "//libexec/rtld-elf:rtld_binary",
                runtime_libraries = ["//lib/libc:c_shared", "//lib/libsys:sys_shared"])
        elif image["encoding"] == "raw":
            native.alias(name = prefix + name, actual = image["source"])
        else:
            fail("unsupported firmware encoding")
        symbol = filename
        for char in ["-", ".", "/", "\\", "@"]:
            symbol = symbol.replace(char, "_")
        _objects(arch = arch, name = name + "_bytes", srcs = ["//sys/kern:firmw.S"],
            additional_compiler_inputs = [":" + prefix + name], local_defines = ["LOCORE", "FIRMW_SYMBOL=" + symbol],
            copts = ["-DFIRMW_FILE=\\\"$(execpath :" + prefix + name + ")\\\"", "-Werror"])
        bsd_object_alias(name = prefix + name + "_object", src = ":" + prefix + name + "_bytes_object_files", output = output_prefix + filename + ".fwo")
        objects.append(":" + prefix + name + "_object")
    bsd_awk_output(name = prefix + "registration_source", script = "//sys/tools:fw_stub.awk", output = output_prefix + module + ".c",
        arguments = specs + ["-m" + module] + (["-l" + license] if license else []),
        awk = "@bsd_sdk//toolchain:awk", redirect = "@bsd_sdk//toolchain:stdout_redirect",
        runtime = ["@bsd_sdk//toolchain:awk_runtime"])
    _objects(arch = arch, name = "registration", srcs = [":" + prefix + "registration_source"],
        copts = ["-fmacro-prefix-map=$(execpath :" + prefix + "registration_source)=" + module + ".c",
                 "-fdebug-prefix-map=$(execpath :" + prefix + "registration_source)=" + module + ".c"])
    arguments = dict(module = module, objects = objects + extra_objects + [":" + prefix + "registration_object_files"],
        object_order = [filename + ".fwo" for filename in filenames] + extra_object_order + [module + ".o"],
        export_all = export_all, package = package)
    if arch == "amd64":
        amd64_generic_module(**arguments)
    else:
        cross_generic_module(arch = arch, **arguments)
