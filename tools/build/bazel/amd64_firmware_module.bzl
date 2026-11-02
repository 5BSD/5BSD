# SPDX-License-Identifier: BSD-2-Clause
"""Compose declared firmware decoding, registration, compilation and module stages."""
load(":amd64_generic_module.bzl", "amd64_generic_module", "amd64_generic_module_objects")
load(":bsd_awk_output.bzl", "bsd_awk_output")
load(":bsd_object_alias.bzl", "bsd_object_alias")
load(":bsd_uudecode.bzl", "bsd_uudecode")


def amd64_firmware_module(module, images, license = "", export_all = False, package = "kernel", extra_objects = [], extra_object_order = []):
    """Images declare source, encoding (raw/uu), filename and original FIRMWS spec."""
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
            bsd_uudecode(name = name, src = image["source"], output = filename,
                decoder = "//usr.bin/bintrans:bintrans", loader = "//libexec/rtld-elf:rtld_binary",
                runtime_libraries = ["//lib/libc:c_shared", "//lib/libsys:sys_shared"])
        elif image["encoding"] == "raw":
            native.alias(name = name, actual = image["source"])
        else:
            fail("unsupported firmware encoding")
        symbol = filename
        for char in ["-", ".", "/", "\\", "@"]:
            symbol = symbol.replace(char, "_")
        amd64_generic_module_objects(name = name + "_bytes", srcs = ["//sys/kern:firmw.S"],
            additional_compiler_inputs = [":" + name], local_defines = ["LOCORE", "FIRMW_SYMBOL=" + symbol],
            copts = ["-DFIRMW_FILE=\\\"$(execpath :" + name + ")\\\"", "-Werror"])
        bsd_object_alias(name = name + "_object", src = ":" + name + "_bytes_object_files", output = filename + ".fwo")
        objects.append(":" + name + "_object")
    bsd_awk_output(name = "registration_source", script = "//sys/tools:fw_stub.awk", output = module + ".c",
        arguments = specs + ["-m" + module] + (["-l" + license] if license else []),
        awk = "@bsd_sdk//toolchain:awk", redirect = "@bsd_sdk//toolchain:stdout_redirect",
        runtime = ["@bsd_sdk//toolchain:awk_runtime"])
    amd64_generic_module_objects(name = "registration", srcs = [":registration_source"],
        copts = ["-fmacro-prefix-map=$(execpath :registration_source)=" + module + ".c",
                 "-fdebug-prefix-map=$(execpath :registration_source)=" + module + ".c"])
    amd64_generic_module(module = module, objects = objects + extra_objects + [":registration_object_files"],
        object_order = [filename + ".fwo" for filename in filenames] + extra_object_order + [module + ".o"],
        export_all = export_all, package = package)
