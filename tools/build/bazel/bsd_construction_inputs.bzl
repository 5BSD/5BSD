# SPDX-License-Identifier: BSD-2-Clause
"""Expose declared fresh-system state to inventory and image consumers."""
load(":bsd_install.bzl", "BsdInstallManifestInfo")
load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo")

CONSTRUCTION_PROVIDERS = [[BsdInstallManifestInfo], [BsdInstallArchiveInfo]]

def construction_inputs(targets):
    records, trees, metadata, payloads = [], [], [], []
    for target in targets:
        info = target[BsdInstallManifestInfo] if BsdInstallManifestInfo in target else target[BsdInstallArchiveInfo]
        records.extend(info.records)
        payloads.append(info.payload)
        if BsdInstallArchiveInfo in target:
            for tree in info.trees:
                trees.append(dict(prefix = tree.prefix, metadata = tree.metadata.path))
                metadata.append(tree.metadata)
    return struct(records = records, trees = trees, metadata = metadata, payloads = payloads)
