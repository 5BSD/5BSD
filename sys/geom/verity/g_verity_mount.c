/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <geom/geom.h>
#include <ufs/ufs/extattr.h>
#include <ufs/ufs/quota.h>
#include <ufs/ufs/ufsmount.h>
#include <geom/verity/g_verity_provider.h>

/* Caller holds this mount busy and excludes mount updates during admission. */
int
g_verity_check_ufs_root(struct mount *mp, const struct g_verity_root *expected)
{
	struct g_verity_cache check;
	struct g_verity_root actual;
	struct ufsmount *ump;
	struct g_consumer *cp;
	int error;

	if (mp == NULL || expected == NULL)
		return (EINVAL);
	error = g_verity_cache_init(&check, expected, NULL, NULL, 0);
	if (error != 0)
		return (error);
	if (mp->mnt_vfc == NULL || strcmp(mp->mnt_vfc->vfc_name, "ufs") != 0 ||
	    (mp->mnt_flag & (MNT_ROOTFS | MNT_RDONLY)) != (MNT_ROOTFS | MNT_RDONLY))
		return (EAUTH);
	ump = VFSTOUFS(mp);
	if (ump == NULL)
		return (ENXIO);
	/* A busy UFS mount retains its consumer; topology protects its provider. */
	g_topology_lock();
	cp = ump->um_cp;
	if (cp == NULL || cp->provider == NULL || cp->acr == 0 || cp->acw != 0)
		error = ENXIO;
	else
		error = g_verity_provider_root(cp->provider, &actual);
	g_topology_unlock();
	if (error != 0)
		return (error);

	/* Compare defined fields, never structure padding or device names. */
	if (actual.filesystem != expected->filesystem ||
	    actual.layout.data_bytes != expected->layout.data_bytes ||
	    actual.layout.tree_bytes != expected->layout.tree_bytes ||
	    actual.layout.block_size != expected->layout.block_size ||
	    actual.layout.levels != expected->layout.levels ||
	    memcmp(actual.layout.offsets, expected->layout.offsets,
	    sizeof(actual.layout.offsets)) != 0 ||
	    actual.salt_len != expected->salt_len ||
	    memcmp(actual.salt, expected->salt, expected->salt_len) != 0 ||
	    memcmp(actual.root_hash, expected->root_hash, sizeof(actual.root_hash)) != 0)
		return (EAUTH);
	return (0);
}
