# SPDX-License-Identifier: BSD-2-Clause
# Source recipe sections preserve order across per-source visibility groups.
ZFS_USER_SOURCES = [
    "//sys/contrib/openzfs:lib/libzfs/libzfs_changelist.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_config.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_crypto.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_dataset.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_diff.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_import.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_iter.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_mnttab.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_mount.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_pool.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_sendrecv.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_share.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_share_nfs.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_status.c",
    "//sys/contrib/openzfs:lib/libzfs/libzfs_util.c",
    "//sys/contrib/openzfs:lib/libzfs/os/freebsd/libzfs_share_nfs.c",
    "//sys/contrib/openzfs:lib/libzfs/os/freebsd/libzfs_share_smb.c",
    "//sys/contrib/openzfs:lib/libzfs/os/freebsd/libzfs_compat.c",
    "//sys/contrib/openzfs:lib/libzfs/os/freebsd/libzfs_zmount.c",
]
ZFS_BTREE_SOURCES = [
    "//sys/contrib/openzfs:module/zfs/btree.c",
]
ZFS_CITYHASH_SOURCES = [
    "//sys/contrib/openzfs:module/zcommon/cityhash.c",
]
ZFS_RANGE_TREE_SOURCES = [
    "//sys/contrib/openzfs:module/zfs/range_tree.c",
]
ZFS_COMMON_SOURCES = [
    "//sys/contrib/openzfs:module/zcommon/zfeature_common.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_comutil.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_deleg.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_fletcher.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_fletcher_superscalar.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_fletcher_superscalar4.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_namecheck.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_prop.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_valstr.c",
    "//sys/contrib/openzfs:module/zcommon/zpool_prop.c",
    "//sys/contrib/openzfs:module/zcommon/zprop_common.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_fletcher_intel.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_fletcher_sse.c",
    "//sys/contrib/openzfs:module/zcommon/zfs_fletcher_avx512.c",
]

# Complete source inventory also drives cross-package source exports.
ZFS_SOURCES = ZFS_USER_SOURCES + ZFS_BTREE_SOURCES + ZFS_CITYHASH_SOURCES + ZFS_RANGE_TREE_SOURCES + ZFS_COMMON_SOURCES
