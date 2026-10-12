/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sha256.h>
#include <capimage.h>
#include <ucl.h>
#include "libcapbundle_internal.h"
#define BUNDLE_DOMAIN "org.5bsd.bundle-inventory.v1"
static int
reject(char *error, size_t size, const char *why)
{
	if (error != NULL && size != 0) snprintf(error, size, "%s", why);
	errno = EAUTH;
	return (-1);
}
/* Verification runs before /tmp or writable root filesystems are available.
 * Use a private anonymous object; inventory() seals it before hashing. */
static FILE *
inventory_stream(void)
{
	int fd = memfd_create("capbundle-inventory", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd < 0) return (NULL);
	FILE *stream = fdopen(fd, "w+");
	if (stream == NULL) {
		int saved = errno;
		close(fd);
		errno = saved;
	}
	return (stream);
}
static int
file_digest(int fd, unsigned char hash[32], unsigned char **capture, size_t *captured)
{
	struct stat st;
	SHA256_CTX ctx;
	unsigned char buffer[16384], *copy = NULL;
	off_t offset = 0;
	int result = -1;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
	    (uint64_t)st.st_size > CAPBUNDLE_MAX_FILE_SIZE)
		return (-1);
	if (capture != NULL) {
		if (st.st_size == 0 || st.st_size > CAPBUNDLE_MAX_UCL_SIZE)
			return (-1);
		copy = malloc((size_t)st.st_size);
		if (copy == NULL) return (-1);
	}
	SHA256_Init(&ctx);
	while (offset < st.st_size) {
		size_t n = (uint64_t)(st.st_size - offset) < sizeof(buffer) ?
		    (size_t)(st.st_size - offset) : sizeof(buffer);
		ssize_t got = pread(fd, buffer, n, offset);
		if (got < 0 && errno == EINTR) continue;
		if (got <= 0) goto out;
		if (copy != NULL) memcpy(copy + offset, buffer, (size_t)got);
		SHA256_Update(&ctx, buffer, (size_t)got);
		offset += got;
	}
	SHA256_Final(hash, &ctx);
	if (capture != NULL) {
		*capture = copy; *captured = (size_t)st.st_size; copy = NULL;
	}
	result = 0;
out:
	free(copy);
	return (result);
}
static int
entry_order(const FTSENT * const *a, const FTSENT * const *b)
{
	return (strcmp((*a)->fts_name, (*b)->fts_name));
}
static int
inventory(const char *path, FILE *out, struct capbundle *bundle)
{
	char root[PATH_MAX], *paths[2];
	FTS *tree;
	FTSENT *entry;
	unsigned count = 0;
	uint64_t total = 0;
	int result = -1;
	if (realpath(path, root) == NULL) return (-1);
	paths[0] = root; paths[1] = NULL;
	tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, entry_order);
	if (tree == NULL) return (-1);
	fprintf(out, "5BSD-BUNDLE-INVENTORY-1\n");
	for (;;) {
		errno = 0;
		entry = fts_read(tree);
		if (entry == NULL) {
			if (errno == 0) result = ferror(out) ? -1 : 0;
			break;
		}
		if (entry->fts_info == FTS_DP || entry->fts_level == 0) continue;
		const char *relative = entry->fts_path + strlen(root) + 1;
		if (strcmp(relative, "Signature") == 0) {
			if (entry->fts_info != FTS_D) break;
			fts_set(tree, entry, FTS_SKIP); continue;
		}
		if (++count > CAPBUNDLE_MAX_TREE_ENTRIES ||
		    (entry->fts_info != FTS_D && entry->fts_info != FTS_F)) break;
		fprintf(out, "%c %04o ", entry->fts_info == FTS_D ? 'D' : 'F',
		    entry->fts_statp->st_mode & 07777);
		for (const unsigned char *p = (const unsigned char *)relative; *p != 0; p++)
			fprintf(out, "%02x", *p);
		if (entry->fts_info == FTS_F) {
			unsigned char digest[32];
			struct stat st;
			int fd = open(entry->fts_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (fd < 0) break;
			bool capture = bundle != NULL && strcmp(relative, "Bundle.ucl") == 0;
			int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 &&
			    (uint64_t)st.st_size <= CAPBUNDLE_MAX_TREE_SIZE - total &&
			    file_digest(fd, digest, capture ? &bundle->signed_bundle_text : NULL,
			    capture ? &bundle->signed_bundle_size : NULL) == 0;
			close(fd);
			if (!ok) break;
			total += (uint64_t)st.st_size;
			fprintf(out, " %ju ", (uintmax_t)st.st_size);
			for (unsigned i = 0; i < 32; i++) fprintf(out, "%02x", digest[i]);
			if (bundle != NULL) {
				struct capbundle_sealed_file *file = calloc(1, sizeof(*file));
				if (file == NULL) break;
				file->path = strdup(relative);
				if (file->path == NULL) { free(file); break; }
				memcpy(file->digest, digest, sizeof(digest));
				file->next = bundle->sealed_files;
				bundle->sealed_files = file;
			}
		}
		fputc('\n', out);
	}
	fts_close(tree);
	if (fflush(out) != 0) result = -1;
	if (result == 0 && fcntl(fileno(out), F_ADD_SEALS,
	    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0)
		result = -1;
	return (result);
}
int
capbundle_seal(const char *path, const char *key, char *error, size_t size)
{
	char directory[PATH_MAX], signature[PATH_MAX], temporary[PATH_MAX];
	FILE *contents;
	int fd, result;
	if (path == NULL || key == NULL) return (reject(error, size, "bundle and key required"));
	if (snprintf(directory, sizeof(directory), "%s/Signature", path) >= (int)sizeof(directory) ||
	    snprintf(signature, sizeof(signature), "%s/Seal", directory) >= (int)sizeof(signature) ||
	    snprintf(temporary, sizeof(temporary), "%s/.seal.XXXXXX", directory) >= (int)sizeof(temporary))
		return (reject(error, size, "bundle path too long"));
	if (mkdir(directory, 0755) < 0 && errno != EEXIST)
		return (reject(error, size, "cannot create signature directory"));
	contents = inventory_stream();
	if (contents == NULL) return (reject(error, size, "cannot create inventory"));
	result = inventory(path, contents, NULL);
	if (result < 0) { fclose(contents); return (reject(error, size, "invalid bundle tree")); }
	fd = mkstemp(temporary);
	if (fd < 0) { fclose(contents); return (reject(error, size, "cannot create seal")); }
	result = capimage_seal(fileno(contents), fd, BUNDLE_DOMAIN, key, error, size);
	if (result == 0 && (fchmod(fd, 0444) < 0 || fsync(fd) < 0 || link(temporary, signature) < 0))
		result = reject(error, size, "cannot publish seal (destination must be new)");
	close(fd); unlink(temporary); fclose(contents);
	return (result);
}
int
capbundle_check_seal(const char *path, const char *key, bool required,
    struct capbundle *bundle, char *error, size_t size)
{
	char directory[PATH_MAX];
	struct stat st;
	DIR *dir;
	struct dirent *entry;
	FILE *contents;
	int fd, result;
	if (snprintf(directory, sizeof(directory), "%s/Signature", path) >= (int)sizeof(directory))
		return (reject(error, size, "bundle path too long"));
	fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT && !required) return (0);
		return (reject(error, size, "signed bundle inventory required"));
	}
	dir = fdopendir(fd);
	if (dir == NULL) { close(fd); return (reject(error, size, "cannot inspect signature directory")); }
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0 &&
		    strcmp(entry->d_name, "Seal") != 0) {
			closedir(dir); return (reject(error, size, "unexpected signature directory entry"));
		}
	}
	fd = openat(dirfd(dir), "Seal", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	closedir(dir);
	if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		if (fd >= 0) close(fd);
		return (reject(error, size, "bundle seal missing or invalid"));
	}
	contents = inventory_stream();
	if (contents == NULL) { close(fd); return (reject(error, size, "cannot create inventory snapshot")); }
	result = inventory(path, contents, bundle);
	if (result == 0)
		result = bundle->personal ?
		    capimage_check_seal_integrity(fileno(contents), fd, BUNDLE_DOMAIN, error, size) :
		    capimage_check_seal(fileno(contents), fd, BUNDLE_DOMAIN, key, error, size);
	else
		reject(error, size, "invalid bundle inventory");
	fclose(contents); close(fd);
	if (result == 0) bundle->signed_bundle = true;
	return (result);
}
static ucl_object_t *
parse_bytes(const unsigned char *data, size_t size, char *error, size_t error_size)
{
	struct ucl_parser *parser = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_FILEVARS);
	ucl_object_t *root = NULL;
	if (parser == NULL) return (NULL);
	if (ucl_parser_add_chunk_full(parser, data, size, 0, UCL_DUPLICATE_ERROR, UCL_PARSE_UCL))
		root = ucl_parser_get_object(parser);
	else if (error != NULL && error_size != 0)
		snprintf(error, error_size, "%s", ucl_parser_get_error(parser));
	ucl_parser_free(parser);
	return (root);
}
static bool
policy_equal(const ucl_object_t *a, const ucl_object_t *b, unsigned depth)
{
	ucl_object_iter_t ai = NULL, bi = NULL;
	const ucl_object_t *child, *other;
	if (a == NULL || b == NULL || depth > 32 || a->type != b->type || a->len != b->len)
		return (false);
	switch (a->type) {
	case UCL_OBJECT:
		while ((child = ucl_object_iterate(a, &ai, true)) != NULL)
			if (!policy_equal(child, ucl_object_lookup(b, ucl_object_key(child)), depth + 1)) return (false);
		return (true);
	case UCL_ARRAY:
		while ((child = ucl_object_iterate(a, &ai, true)) != NULL) {
			other = ucl_object_iterate(b, &bi, true);
			if (!policy_equal(child, other, depth + 1)) return (false);
		}
		return (true);
	case UCL_STRING: return (memcmp(ucl_object_tostring(a), ucl_object_tostring(b), a->len) == 0);
	case UCL_INT: return (ucl_object_toint(a) == ucl_object_toint(b));
	case UCL_BOOLEAN: return (ucl_object_toboolean(a) == ucl_object_toboolean(b));
	case UCL_FLOAT: case UCL_TIME: return (ucl_object_todouble(a) == ucl_object_todouble(b));
	case UCL_NULL: return (true);
	default: return (false);
	}
}
int
capbundle_load_unit_policy(const char *path, const char *unit_path,
    const struct capbundle *bundle, const char *unit, struct capbundle_service *svc,
    ucl_object_t **out, char *error, size_t size)
{
	struct capimage_policy policy;
	unsigned char hash[32], *bytes = NULL, ident[4];
	size_t length = 0;
	ucl_object_t *external = NULL, *embedded = NULL;
	const ucl_object_t *selected, *v, *profiles;
	char program[CAPBUNDLE_NAME_MAX + 1], image[PATH_MAX], relative[PATH_MAX], label[256];
	int fd, handle = -1, preparation_error = 0, result = -1;
	*out = NULL;
	if (error != NULL && size != 0) error[0] = '\0';
	/* Signed deployments derive unit policy only from the executable.
	 * External Unit.ucl is an unsigned-development/build input. */
	if (bundle->require_signatures) { fd = -1; errno = ENOENT; }
	else fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_VERIFY);
	if (fd >= 0) {
		if (file_digest(fd, hash, &bytes, &length) == 0) external = parse_bytes(bytes, length, error, size);
		close(fd); free(bytes);
		if (external == NULL || external->type != UCL_OBJECT) goto invalid;
		v = ucl_object_lookup(external, "program");
		const char *name = v == NULL ? unit : ucl_object_tostring(v);
		if (name == NULL || strlcpy(program, name, sizeof(program)) >= sizeof(program)) goto invalid;
	} else if (errno == ENOENT && bundle->signed_bundle) {
		/* The authenticated inventory already names all regular files.
		 * Reuse it instead of reopening and scanning the unit directory. */
		unsigned n = 0;
		if (snprintf(relative, sizeof(relative), "Units/%s.unit/bin/", unit) >= (int)sizeof(relative)) goto invalid;
		size_t prefix = strlen(relative);
		for (const struct capbundle_sealed_file *f = bundle->sealed_files; f != NULL; f = f->next) {
			if (strncmp(f->path, relative, prefix) != 0 || strchr(f->path + prefix, '/') != NULL) continue;
			if (++n > 1 || strlcpy(program, f->path + prefix, sizeof(program)) >= sizeof(program)) goto invalid;
		}
		if (n != 1) goto invalid;
	} else if (errno == ENOENT) {
		DIR *dir;
		struct dirent *entry;
		unsigned n = 0;
		if (snprintf(image, sizeof(image), "%s/bin", unit_path) >= (int)sizeof(image)) goto invalid;
		dir = opendir(image);
		if (dir == NULL) goto invalid;
		while ((entry = readdir(dir)) != NULL) {
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
			struct stat candidate;
			if (fstatat(dirfd(dir), entry->d_name, &candidate, AT_SYMLINK_NOFOLLOW) < 0) { n = 0; break; }
			if (S_ISDIR(candidate.st_mode)) continue;
			if (!S_ISREG(candidate.st_mode)) { n = 0; break; }
			if (++n > 1 || strlcpy(program, entry->d_name, sizeof(program)) >= sizeof(program)) break;
		}
		closedir(dir);
		if (n != 1) goto invalid;
	} else goto invalid;
	if (program[0] == 0 || strchr(program, '/') != NULL || strcmp(program, ".") == 0 || strcmp(program, "..") == 0 ||
	    snprintf(image, sizeof(image), "%s/bin/%s", unit_path, program) >= (int)sizeof(image)) goto invalid;
	fd = open(image, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_VERIFY);
	if (fd < 0) {
		/* Legacy validation may inspect manifests before the program exists.
		 * Verification of a complete bundle still rejects missing programs. */
		if (!bundle->require_signatures && external != NULL && errno == ENOENT) {
			*out = external; return (0);
		}
		goto invalid;
	}
	bool elf = bundle->require_signatures ||
	    (pread(fd, ident, sizeof(ident), 0) == sizeof(ident) && memcmp(ident, ELFMAG, SELFMAG) == 0);
	if (!elf) errno = ENOENT;
	int verified = -1;
#ifdef CAPIMAGE_EXPERIMENTAL_CONSUMER
	if (elf) {
		struct capimage_info info;
		verified = bundle->personal ?
		    capimage_prepare_fd(fd, CAPIMAGE_PREPARE_REQUIRED, &handle,
		    &info, error, size) :
		    capimage_prepare_trusted_fd(fd, CAPIMAGE_PREPARE_REQUIRED,
		    bundle->verification_key, &handle, &info, error, size);
		if (verified == 0)
			verified = capimage_handle_policy(handle, &policy, error, size);
		if (verified < 0)
			preparation_error = errno;
	}
#else
	if (elf)
		verified = bundle->personal ?
		    capimage_verify_integrity(fd, &policy, error, size) :
		    capimage_verify(fd, bundle->verification_key, &policy, error, size);
#endif
	if (!elf || verified < 0) {
		int saved = errno;
		close(fd);
		if (handle >= 0) { close(handle); handle = -1; }
		if ((saved == ENOENT || saved == ENOATTR) &&
		    !bundle->require_signatures && external != NULL) {
			*out = external; return (0);
		}
		goto invalid;
	}
	close(fd);
	embedded = parse_bytes(policy.data, policy.size, error, size);
	memcpy(svc->image_digest, policy.digest, sizeof(svc->image_digest));
	capimage_policy_free(&policy);
	if (embedded == NULL || embedded->type != UCL_OBJECT) goto invalid;
	selected = embedded;
	profiles = ucl_object_lookup(embedded, "profiles");
	if (profiles != NULL) {
		if (embedded->len != 1 || profiles->type != UCL_OBJECT || profiles->len > CAPBUNDLE_MAX_SERVICES ||
		    snprintf(label, sizeof(label), "%s/%s", bundle->bundle_id, unit) >= (int)sizeof(label)) goto invalid;
		selected = ucl_object_lookup(profiles, label);
		if (selected == NULL || selected->type != UCL_OBJECT) goto invalid;
	}
	if (external != NULL && !policy_equal(external, selected, 0)) goto invalid;
	v = ucl_object_lookup(selected, "program");
	if ((v != NULL && (ucl_object_tostring(v) == NULL || strcmp(ucl_object_tostring(v), program) != 0)) ||
	    (v == NULL && strcmp(unit, program) != 0)) goto invalid;
	svc->personal = bundle->personal;
	svc->signed_image = true;
	if (bundle->signed_bundle) {
		if (snprintf(relative, sizeof(relative), "Units/%s.unit/bin/%s", unit, program) >= (int)sizeof(relative)) goto invalid;
		const struct capbundle_sealed_file *f;
		for (f = bundle->sealed_files; f != NULL; f = f->next)
			if (strcmp(f->path, relative) == 0) break;
		if (f == NULL) goto invalid;
		svc->sealed_image = true;
		memcpy(svc->sealed_image_digest, f->digest, sizeof(f->digest));
	}
	*out = ucl_object_ref(selected);
	result = 0;
invalid:
	if (handle >= 0) close(handle);
	ucl_object_unref(external); ucl_object_unref(embedded);
	if (result < 0) {
		if (error == NULL || size == 0 || error[0] == '\0')
			reject(error, size, "embedded policy missing, untrusted, or inconsistent with unit");
		else errno = EAUTH;
		if (preparation_error != 0) errno = preparation_error;
	}
	return (result);
}
int
capbundle_svc_verify_image(const struct capbundle_service *svc, int fd,
    const char *key, char *error, size_t size)
{
	struct capimage_policy policy;
	unsigned char digest[32];
	if (svc == NULL) return (reject(error, size, "unit required"));
	if (!svc->signed_image) return (0);
	if ((svc->personal ? capimage_verify_integrity(fd, &policy, error, size) :
	    capimage_verify(fd, key, &policy, error, size)) < 0) return (-1);
	bool same = memcmp(svc->image_digest, policy.digest, sizeof(policy.digest)) == 0;
	capimage_policy_free(&policy);
	if (same && svc->sealed_image)
		same = file_digest(fd, digest, NULL, NULL) == 0 &&
		    memcmp(digest, svc->sealed_image_digest, sizeof(digest)) == 0;
	return (same ? 0 : reject(error, size, "executable differs from verified unit or bundle"));
}

int
capbundle_svc_prepare_image(const struct capbundle_service *svc, int fd,
    const char *key, int *handle, char *error, size_t size)
{
	struct capimage_info info;
	uint32_t flags = CAPIMAGE_PREPARE_REQUIRED;
	int result;

	if (handle == NULL)
		return (reject(error, size, "image handle output required"));
	*handle = -1;
	if (svc == NULL)
		return (reject(error, size, "unit required"));
	if (!svc->signed_image)
		return (0);
	if (svc->sealed_image)
		flags |= CAPIMAGE_PREPARE_RAW_DIGEST;
	result = svc->personal ?
	    capimage_prepare_fd(fd, flags, handle, &info, error, size) :
	    capimage_prepare_trusted_fd(fd, flags, key, handle, &info, error, size);
	if (result < 0)
		return (-1);
	if (*handle < 0 || memcmp(svc->image_digest, info.image_digest, 32) != 0 ||
	    (svc->sealed_image && ((info.available & CAPIMAGE_INFO_RAW_DIGEST) == 0 ||
	    memcmp(svc->sealed_image_digest, info.raw_digest, 32) != 0))) {
		if (*handle >= 0) close(*handle);
		*handle = -1;
		return (reject(error, size, "executable differs from verified unit or bundle"));
	}
	return (0);
}
