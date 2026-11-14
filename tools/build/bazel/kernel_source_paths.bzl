# SPDX-License-Identifier: BSD-2-Clause
"""Logical compiler provenance for declared kernel module sources."""

def module_relative_source_identity(module_directory, relative_source_directory):
    """Preserve a module's declared relative source directory as logical identity.

    Resolve only the compiler-input prefix; retain the original relative spelling
    in diagnostic/debug paths. Neither the checkout root nor ELF output is read.
    """
    if any([c in module_directory + relative_source_directory for c in ["=", "\\", "\n", "\r", "\000"]]):
        fail("invalid module source identity path")
    parts = module_directory.split("/")
    if any([part in ["", ".", ".."] for part in parts]):
        fail("module directory must be a canonical repository-relative path")
    for part in relative_source_directory.split("/"):
        if part == "..":
            if not parts:
                fail("module source directory escapes the repository")
            parts.pop()
        elif part in ["", "."]:
            fail("source directory must have explicit nonempty path components")
        else:
            parts.append(part)
    if not parts:
        fail("module source directory cannot be the repository root")
    return struct(source_prefix = "/".join(parts),
        logical_prefix = "/usr/src/" + module_directory + "/" + relative_source_directory)

def _logical_path(path, identity):
    if identity != None and (path == identity.source_prefix or path.startswith(identity.source_prefix + "/")):
        return identity.logical_prefix + path[len(identity.source_prefix):]
    return "/usr/src/" + path

def module_identity_prefix_maps(identity):
    if identity == None:
        return []
    return ["-ffile-prefix-map=" + prefix + identity.source_prefix + "/=" + identity.logical_prefix + "/"
            for prefix in ["", "./"]]

def module_source_path_maps(source, identity = None):
    """Normalize declared source paths, including quote-search ./ spellings."""
    if source.startswith("@"):
        return []
    if source.startswith("//"):
        label = source
        package, target = source[2:].split(":", 1)
    else:
        package = native.package_name()
        target = source[1:] if source.startswith(":") else source
        label = "//%s:%s" % (package, target)
    source_path = (package + "/" if package else "") + target
    logical_path = _logical_path(source_path, identity)
    mappings = [
        "-fmacro-prefix-map=$(execpath %s)=%s" % (label, logical_path),
        "-fmacro-prefix-map=./$(execpath %s)=%s" % (label, logical_path),
    ]
    if package:
        mappings.append("-fdebug-prefix-map=%s=%s" % (package, _logical_path(package, identity)))
    mappings.append("-fdebug-prefix-map=$(execpath %s)=%s" % (label, logical_path))
    mappings.append("-fdebug-prefix-map=./$(execpath %s)=%s" % (label, logical_path))
    return mappings
