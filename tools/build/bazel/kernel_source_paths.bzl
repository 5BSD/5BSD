# SPDX-License-Identifier: BSD-2-Clause
"""Canonical compiler provenance for declared kernel module sources."""

def module_source_path_maps(source):
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
    mappings = [
        "-fmacro-prefix-map=$(execpath %s)=/usr/src/%s" % (label, source_path),
        "-fmacro-prefix-map=./$(execpath %s)=/usr/src/%s" % (label, source_path),
    ]
    if package:
        mappings.append("-fdebug-prefix-map=%s=/usr/src/%s" % (package, package))
    mappings.append("-fdebug-prefix-map=$(execpath %s)=/usr/src/%s" % (label, source_path))
    mappings.append("-fdebug-prefix-map=./$(execpath %s)=/usr/src/%s" % (label, source_path))
    return mappings
