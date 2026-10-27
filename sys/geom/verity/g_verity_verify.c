/* SPDX-License-Identifier: BSD-2-Clause */
/* Independent dm-verity v1 SHA-256 verifier; no on-disk superblock. */
#include <sys/types.h>
#include <sys/endian.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/errno.h>
#else
#include <errno.h>
#include <stdint.h>
#include <string.h>
#endif
#include <crypto/sha2/sha256.h>
#include "g_verity_verify.h"

int
g_verity_layout(uint64_t bytes, uint32_t block, struct g_verity_layout *layout)
{
	uint64_t counts[G_VERITY_LEVELS], count, total, fanout;
	unsigned int levels, i;

	if (layout == NULL || block < 512 || block > 65536 ||
	    (block & (block - 1)) != 0 || bytes > INT64_MAX ||
	    bytes < 2 * (uint64_t)block || bytes % block != 0)
		return (EINVAL);
	count = bytes / block;
	fanout = block / SHA256_DIGEST_LENGTH;
	for (levels = 0; count > 1; levels++) {
		if (levels == G_VERITY_LEVELS)
			return (EOVERFLOW);
		count = count / fanout + (count % fanout != 0);
		counts[levels] = count;
	}
	memset(layout, 0, sizeof(*layout));
	total = 0;
	for (i = levels; i > 0; i--) {
		if (counts[i - 1] > ((uint64_t)INT64_MAX - total) / block)
			return (EOVERFLOW);
		layout->offsets[i - 1] = total;
		total += counts[i - 1] * block;
	}
	layout->data_bytes = bytes;
	layout->block_size = block;
	layout->tree_bytes = total;
	layout->levels = levels;
	return (0);
}

static void
block_hash(const void *salt, size_t salt_len, const void *data, size_t length,
    uint8_t digest[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX context;

	SHA256_Init(&context);
	if (salt_len != 0)
		SHA256_Update(&context, salt, salt_len);
	SHA256_Update(&context, data, length);
	SHA256_Final(digest, &context);
}

static int
verify_block(const struct g_verity_layout *layout, const void *salt,
    size_t salt_len, const uint8_t root[32], uint64_t index,
    g_verity_read_t *reader, void *arg, void *data, void *hashes, void *output,
    void *leaf)
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint64_t parent, slot, child;
	uint32_t block = layout->block_size;
	unsigned int level;
	int error;

	error = reader(arg, 0, index * block, data, block);
	if (error != 0)
		return (error);
	block_hash(salt, salt_len, data, block, digest);
	child = index;
	for (level = 0; level < layout->levels; level++) {
		parent = child / (block / SHA256_DIGEST_LENGTH);
		slot = child % (block / SHA256_DIGEST_LENGTH);
		error = reader(arg, 1, layout->offsets[level] + parent * block,
		    hashes, block);
		if (error != 0)
			return (error);
		if (memcmp(digest, (uint8_t *)hashes + slot * SHA256_DIGEST_LENGTH,
		    sizeof(digest)) != 0)
			return (EAUTH);
		/* The caller may use these bytes only after the root check succeeds. */
		if (level == 0 && leaf != NULL)
			memcpy(leaf, hashes, block);
		block_hash(salt, salt_len, hashes, block, digest);
		child = parent;
	}
	if (memcmp(digest, root, sizeof(digest)) != 0)
		return (EAUTH);
	if (output != data)
		memcpy(output, data, block);
	return (0);
}

int
g_verity_verify(uint64_t bytes, uint32_t block, const void *salt, size_t salt_len,
    const uint8_t root[32], uint64_t index, g_verity_read_t *reader, void *arg,
    void *data, void *hashes, void *output)
{
	struct g_verity_layout layout;
	int error;

	error = g_verity_layout(bytes, block, &layout);
	if (error != 0)
		return (error);
	if (index >= bytes / block || salt_len > 256 ||
	    (salt_len != 0 && salt == NULL) || root == NULL || reader == NULL ||
	    data == NULL || hashes == NULL || output == NULL)
		return (EINVAL);
	return (verify_block(&layout, salt, salt_len, root, index, reader, arg,
	    data, hashes, output, NULL));
}

int
g_verity_read_range(uint64_t bytes, uint32_t block, const void *salt,
    size_t salt_len, const uint8_t root[32], uint64_t offset, size_t length,
    g_verity_read_t *reader, void *arg, void *data, void *hashes,
    void *verified, void *output)
{
	struct g_verity_layout layout;
	size_t done, skip, take;
	uint64_t position, index, parent, cached_parent = UINT64_MAX;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	int error;

	error = g_verity_layout(bytes, block, &layout);
	if (error != 0)
		return (error);
	if (offset > bytes || length > bytes - offset || salt_len > 256 ||
	    (salt_len != 0 && salt == NULL) || root == NULL || reader == NULL ||
	    data == NULL || hashes == NULL || verified == NULL || output == NULL)
		return (EINVAL);
	for (done = 0; done < length; done += take) {
		position = offset + done;
		skip = position % block;
		take = block - skip;
		if (take > length - done)
			take = length - done;
		index = position / block;
		parent = index / (block / SHA256_DIGEST_LENGTH);
		if (parent != cached_parent) {
			error = verify_block(&layout, salt, salt_len, root, index,
			    reader, arg, data, hashes, data, verified);
			if (error == 0)
				cached_parent = parent;
		} else {
			/* Reuse authenticated leaf bytes, never a previously-valid
			 * flag for mutable backing bytes. Every data read is hashed.
			 * Cache identity and lifetime are confined to this request. */
			error = reader(arg, 0, index * block, data, block);
			if (error == 0) {
				block_hash(salt, salt_len, data, block, digest);
				if (memcmp(digest, (uint8_t *)verified +
				    (index % (block / SHA256_DIGEST_LENGTH)) *
				    SHA256_DIGEST_LENGTH, sizeof(digest)) != 0)
					error = EAUTH;
			}
		}
		if (error != 0) {
			/* No partial successful request may escape to the consumer. */
			memset(output, 0, length);
			return (error);
		}
		memcpy((uint8_t *)output + done, (uint8_t *)data + skip, take);
	}
	return (0);
}

int
g_verity_root_decode(const void *wire, size_t length, struct g_verity_root *root)
{
	struct g_verity_root decoded;
	const uint8_t *bytes;
	uint32_t salt_len;
	size_t i;
	int error;

	if (wire == NULL || root == NULL || length != G_VERITY_ROOT_BYTES)
		return (EINVAL);
	bytes = wire;
	if (memcmp(bytes, "BIPROOT\0", 8) != 0 ||
	    be32dec(bytes + 8) != 1 || be32dec(bytes + 12) != length ||
	    be32dec(bytes + 16) != 1 || /* dm-verity v1 */
	    be32dec(bytes + 20) != 1 || /* SHA-256 */
	    be32dec(bytes + 24) != 1)   /* UFS2 */
		return (EINVAL);
	salt_len = be32dec(bytes + 80);
	if (salt_len > sizeof(decoded.salt))
		return (EINVAL);
	/* Unused salt and reserved bytes must be canonical zero padding. */
	for (i = 84 + salt_len; i < G_VERITY_ROOT_BYTES; i++)
		if (bytes[i] != 0)
			return (EINVAL);
	memset(&decoded, 0, sizeof(decoded));
	error = g_verity_layout(be64dec(bytes + 32), be32dec(bytes + 28),
	    &decoded.layout);
	if (error != 0)
		return (error);
	if (be64dec(bytes + 40) != decoded.layout.tree_bytes)
		return (EINVAL);
	memcpy(decoded.root_hash, bytes + 48, sizeof(decoded.root_hash));
	memcpy(decoded.salt, bytes + 84, salt_len);
	decoded.salt_len = salt_len;
	decoded.filesystem = 1;
	*root = decoded;
	return (0);
}

/* Cache is private to one authenticated root and externally serialized.
 * Tags identify retained verified bytes, never mutable backing-store status. */
int
g_verity_cache_init(struct g_verity_cache *cache,
    const struct g_verity_root *root, uint64_t *tags, void *blocks, size_t entries)
{
 struct g_verity_layout layout;
 struct g_verity_cache fresh;
 size_t i;
 int error;

 if (cache == NULL || root == NULL || root->salt_len > sizeof(root->salt) ||
     root->filesystem != 1)
  return (EINVAL);
 error = g_verity_layout(root->layout.data_bytes, root->layout.block_size, &layout);
 if (error != 0)
  return (error);
 if (root->layout.tree_bytes != layout.tree_bytes ||
     root->layout.levels != layout.levels ||
     entries > SIZE_MAX / layout.block_size ||
     (entries != 0 && (tags == NULL || blocks == NULL)))
  return (EINVAL);
 for (i = 0; i < G_VERITY_LEVELS; i++)
  if (root->layout.offsets[i] != layout.offsets[i])
   return (EINVAL);
 memset(&fresh, 0, sizeof(fresh));
 fresh.root = *root;
 fresh.tags = tags;
 fresh.blocks = blocks;
 fresh.entries = entries;
 fresh.initialized = 1;
 for (i = 0; i < entries; i++)
  tags[i] = UINT64_MAX;
 *cache = fresh;
 return (0);
}

static int
cached_verify_block(struct g_verity_cache *cache, uint64_t index,
    g_verity_read_t *reader, void *arg, void *data, void *hashes)
{
 const struct g_verity_root *root = &cache->root;
 const struct g_verity_layout *layout = &root->layout;
 uint64_t children[G_VERITY_LEVELS], child = index, offset;
 uint8_t expected[32], digest[32];
 const uint8_t *node;
 uint32_t block = layout->block_size, fanout = block / 32;
 size_t slot = 0;
 unsigned level;
 int error;

 for (level = 0; level < layout->levels; level++) {
  children[level] = child;
  child /= fanout;
 }
 memcpy(expected, root->root_hash, sizeof(expected));
 for (level = layout->levels; level > 0; level--) {
  child = children[level - 1];
  offset = layout->offsets[level - 1] + (child / fanout) * block;
  if (cache->entries != 0)
   slot = (offset / block) % cache->entries;
  if (cache->entries != 0 && cache->tags[slot] == offset) {
   node = (uint8_t *)cache->blocks + slot * block;
  } else {
   error = reader(arg, 1, offset, hashes, block);
   if (error != 0)
    return (error);
   block_hash(root->salt, root->salt_len, hashes, block, digest);
   if (memcmp(digest, expected, sizeof(digest)) != 0)
    return (EAUTH);
   if (cache->entries != 0) {
    memcpy((uint8_t *)cache->blocks + slot * block, hashes, block);
    cache->tags[slot] = offset;
   }
   node = hashes;
  }
  memcpy(expected, node + (child % fanout) * 32, sizeof(expected));
 }
 /* Preserve the authenticated leaf across this request, even on eviction. */
 if (node != hashes)
  memcpy(hashes, node, block);
 error = reader(arg, 0, index * block, data, block);
 if (error != 0)
  return (error);
 block_hash(root->salt, root->salt_len, data, block, digest);
 return (memcmp(digest, expected, sizeof(digest)) == 0 ? 0 : EAUTH);
}

int
g_verity_cached_read_range(struct g_verity_cache *cache, uint64_t offset,
    size_t length, g_verity_read_t *reader, void *arg, void *data,
    void *hashes, void *output)
{
 size_t done, take, skip;
 uint64_t position, index, parent, cached_parent = UINT64_MAX;
 uint8_t digest[32];
 uint32_t block;
 int error;

 if (cache == NULL || cache->initialized != 1 || reader == NULL ||
     data == NULL || hashes == NULL || output == NULL)
  return (EINVAL);
 if (offset > cache->root.layout.data_bytes ||
     length > cache->root.layout.data_bytes - offset)
  return (EINVAL);
 block = cache->root.layout.block_size;
 for (done = 0; done < length; done += take) {
  position = offset + done;
  skip = position % block;
  take = block - skip;
  if (take > length - done)
   take = length - done;
  index = position / block;
  parent = index / (block / 32);
  if (parent != cached_parent) {
   error = cached_verify_block(cache, index, reader, arg, data, hashes);
   if (error == 0)
    cached_parent = parent;
  } else {
   error = reader(arg, 0, index * block, data, block);
   if (error == 0) {
    block_hash(cache->root.salt, cache->root.salt_len, data, block, digest);
    if (memcmp(digest, (uint8_t *)hashes + (index % (block / 32)) * 32,
        sizeof(digest)) != 0)
     error = EAUTH;
   }
  }
  if (error != 0) {
   memset(output, 0, length);
   return (error);
  }
  memcpy((uint8_t *)output + done, (uint8_t *)data + skip, take);
 }
 return (0);
}
