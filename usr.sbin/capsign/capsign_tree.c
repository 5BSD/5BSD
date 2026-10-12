/* SPDX-License-Identifier: BSD-2-Clause */
/* Recursive operations on a new, private copy. No running bundle is modified. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/elf_common.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <capimage.h>
#include <libcapbundle.h>
#include "capsign_tree.h"
#define TREE_ENTRIES_MAX 65536U
#define TREE_BYTES_MAX (8ULL * 1024 * 1024 * 1024)
static char *public_temporary;
static void cleanup_public(void) { if (public_temporary != NULL) unlink(public_temporary); }
static char *preview_directory;
static int
remove_preview(void)
{
    char *paths[] = { preview_directory, NULL };
    FTS *tree;
    FTSENT *entry;
    int failed = 0;
    if (preview_directory == NULL) return (0);
    tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (tree == NULL) return (-1);
    for (;;) {
        errno = 0;
        entry = fts_read(tree);
        if (entry == NULL) { if (errno != 0) failed = -1; break; }
        switch (entry->fts_info) {
        case FTS_D:
            if (chmod(entry->fts_path, 0700) < 0) failed = -1;
            break;
        case FTS_DNR:
            if (entry->fts_number != 0 || chmod(entry->fts_path, 0700) < 0)
                failed = -1;
            else {
                entry->fts_number = 1;
                if (fts_set(tree, entry, FTS_AGAIN) < 0) failed = -1;
            }
            break;
        case FTS_DP:
            if (rmdir(entry->fts_path) < 0) failed = -1;
            break;
        case FTS_ERR:
            failed = -1;
            break;
        default:
            if (unlink(entry->fts_path) < 0) failed = -1;
            break;
        }
    }
    if (fts_close(tree) < 0) failed = -1;
    if (failed == 0) { free(preview_directory); preview_directory = NULL; }
    return (failed);
}
static void
cleanup_preview(void)
{
    if (remove_preview() < 0)
        warnx("cannot completely remove dry-run directory %s", preview_directory);
}
static void
copy_bytes(int in, int out, off_t size)
{
    unsigned char buffer[16384];
    for (off_t pos = 0; pos < size;) {
        size_t len = size-pos < (off_t)sizeof(buffer) ? (size_t)(size-pos) : sizeof(buffer);
        ssize_t n = pread(in, buffer, len, pos);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) errx(1, "short source read");
        for (ssize_t done = 0; done < n;) {
            ssize_t wrote = pwrite(out, buffer+done, (size_t)(n-done), pos+done);
            if (wrote < 0 && errno == EINTR) continue;
            if (wrote <= 0) err(1, "write copied image");
            done += wrote;
        }
        pos += n;
    }
}
static bool is_bundle(const char *name)
{
    size_t n = strlen(name);
    return (n > 4 && strcmp(name+n-4, ".cap") == 0);
}
static char *
public_key(const char *private, const char *output)
{
    FILE *in = fopen(private, "r"), *out;
    EVP_PKEY *key;
    int fd;
    if (in == NULL) err(1, "%s", private);
    key = PEM_read_PrivateKey(in, NULL, NULL, NULL);
    fclose(in);
    if (key == NULL || EVP_PKEY_base_id(key) != EVP_PKEY_ED25519)
        errx(1, "an Ed25519 signing key is required");
    if (asprintf(&public_temporary, "%s.public.XXXXXX", output) < 0) err(1, "public key path");
    atexit(cleanup_public);
    fd = mkstemp(public_temporary);
    if (fd < 0 || (out = fdopen(fd, "w")) == NULL) err(1, "public key temporary");
    if (PEM_write_PUBKEY(out, key) != 1 || fclose(out) != 0) errx(1, "write public key");
    EVP_PKEY_free(key);
    return (public_temporary);
}
static void
clone_tree(const char *source, const char *destination, bool sealed)
{
    char root[PATH_MAX], output[PATH_MAX], *paths[2];
    struct stat st;
    unsigned entries = 0;
    uint64_t total = 0;
    FTS *tree;
    FTSENT *entry;
    if (lstat(source, &st) < 0 || !S_ISDIR(st.st_mode) || realpath(source, root) == NULL)
        errx(1, "source must be a real directory");
    char parent[PATH_MAX], canonical[PATH_MAX];
    if (strlcpy(parent, destination, sizeof(parent)) >= sizeof(parent)) errx(1, "output path too long");
    char *base = strrchr(parent, '/');
    const char *leaf = destination;
    if (base != NULL) { leaf = strrchr(destination, '/') + 1; *base = 0; }
    if (realpath(base == NULL ? "." : (parent[0] == 0 ? "/" : parent), canonical) == NULL)
        err(1, "output parent");
    if (leaf[0] == 0 || strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0 ||
        snprintf(output, sizeof(output), "%s/%s", canonical, leaf) >= (int)sizeof(output))
        errx(1, "invalid output path");
    size_t rootlen = strlen(root);
    if (strcmp(root, "/") == 0 ||
        (strncmp(output, root, rootlen) == 0 && (output[rootlen] == '/' || output[rootlen] == 0)))
        errx(1, "output directory must be outside the source tree");
    if (is_bundle(strrchr(root, '/') + 1) && !is_bundle(leaf))
        errx(1, "single bundle output must end in .cap");
    if (mkdir(destination, 0700) < 0) err(1, "new output directory %s", destination);
    paths[0] = root; paths[1] = NULL;
    tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (tree == NULL) err(1, "source tree");
    for (;;) {
        errno = 0;
        entry = fts_read(tree);
        if (entry == NULL) { if (errno != 0) err(1, "source traversal"); break; }
        if (entry->fts_level == 0) continue;
        if (entry->fts_info == FTS_DP && !sealed) continue;
        if (entry->fts_info != FTS_DP && ++entries > TREE_ENTRIES_MAX) errx(1, "tree entry limit exceeded");
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s%s", output, entry->fts_path+rootlen) >= (int)sizeof(path))
            errx(1, "output path too long");
        if (entry->fts_info == FTS_DP) {
            if (chmod(path, entry->fts_statp->st_mode & 0777) < 0) err(1, "preserve copied directory mode");
        } else if (entry->fts_info == FTS_D) {
            if (!sealed && strcmp(entry->fts_name, "Signature") == 0)
                errx(1, "already sealed tree: %s", entry->fts_path);
            if (mkdir(path, (entry->fts_statp->st_mode & 0777) | 0700) < 0) err(1, "%s", path);
        } else if (entry->fts_info == FTS_F) {
            int in = open(entry->fts_accpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (in < 0 || fstat(in, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
                (st.st_mode & (S_ISUID | S_ISGID)) || (uint64_t)st.st_size > CAPIMAGE_FILE_MAX ||
                (uint64_t)st.st_size > TREE_BYTES_MAX-total)
                errx(1, "unsupported source file: %s", entry->fts_path);
            total += st.st_size;
            int out = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (out < 0) err(1, "%s", path);
            copy_bytes(in, out, st.st_size);
            if (fchmod(out, st.st_mode & 0777) < 0 || fsync(out) < 0 || close(out) < 0) err(1, "finish copied file");
            close(in);
        } else errx(1, "symlink or unsupported entry: %s", entry->fts_path);
    }
    fts_close(tree);
}
static void
sign_bundle(const char *path, const char *key, const char *public)
{
    struct capbundle *bundle;
    char error[256], manifest[PATH_MAX];
    if (capbundle_open_trusted(path, public, false, &bundle, error, sizeof(error)) < 0)
        errx(1, "%s: %s", path, error);
    for (unsigned i = 0; i < capbundle_nservices(bundle); i++) {
        const char *image = capbundle_svc_program(capbundle_service(bundle, i));
        if (strlcpy(manifest, image, sizeof(manifest)) >= sizeof(manifest)) errx(1, "image path too long");
        char *slash = strrchr(manifest, '/');
        if (slash == NULL) errx(1, "invalid unit program path");
        *slash = 0; slash = strrchr(manifest, '/');
        if (slash == NULL || strcmp(slash, "/bin") != 0) errx(1, "program outside unit bin");
        if (strlcpy(slash+1, "Unit.ucl", (size_t)(manifest+sizeof(manifest)-slash-1)) >=
            (size_t)(manifest+sizeof(manifest)-slash-1)) errx(1, "manifest path too long");
        struct stat image_st;
        int fd = open(image, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 || fstat(fd, &image_st) < 0 ||
            fchmod(fd, (image_st.st_mode & 0777) | S_IWUSR) < 0) err(1, "%s", image);
        close(fd);
        fd = open(image, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) err(1, "%s", image);
        int signed_existing = capimage_sign(fd, key, error, sizeof(error));
        if (signed_existing < 0 && errno != ENOENT) errx(1, "%s: %s", image, error);
        int mfd = open(manifest, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (mfd >= 0 && signed_existing < 0) {
            struct stat st;
            if (fstat(mfd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
                st.st_size > CAPIMAGE_POLICY_MAX) errx(1, "invalid unit manifest");
            unsigned char *data = malloc((size_t)st.st_size);
            if (data == NULL) err(1, "manifest allocation");
            off_t pos = 0;
            while (pos < st.st_size) {
                ssize_t n = pread(mfd, data+pos, (size_t)(st.st_size-pos), pos);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) errx(1, "short unit manifest read");
                pos += n;
            }
            if (capimage_embed(fd, data, (size_t)st.st_size, error, sizeof(error)) < 0) errx(1, "%s: %s", image, error);
            free(data); close(mfd);
        } else if (mfd >= 0) close(mfd);
        else if (errno != ENOENT) err(1, "%s", manifest);
        if (capimage_sign(fd, key, error, sizeof(error)) < 0 || fchmod(fd, image_st.st_mode & 0777) < 0 || fsync(fd) < 0)
            errx(1, "%s: %s", image, error);
        close(fd);
        /* The private signed output carries policy only in its executable. */
        if (unlink(manifest) < 0 && errno != ENOENT) err(1, "%s", manifest);
    }
    capbundle_close(bundle);
    if (capbundle_seal(path, key, error, sizeof(error)) < 0) errx(1, "%s: %s", path, error);
}
/* First preserve directory modes for verification, then make only the new
 * private output owner-accessible before changing images and parent seals. */
static unsigned
prepare_tree(const char *path)
{
    char root[PATH_MAX], *paths[2];
    unsigned removed = 0;
    if (realpath(path, root) == NULL) err(1, "%s", path);
    paths[0] = root; paths[1] = NULL;
    FTS *tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (tree == NULL) err(1, "private tree traversal");
    for (;;) {
        errno = 0;
        FTSENT *entry = fts_read(tree);
        if (entry == NULL) { if (errno != 0) err(1, "private tree traversal"); break; }
        if (entry->fts_info == FTS_D) {
            if (chmod(entry->fts_path, (entry->fts_statp->st_mode & 0777) | 0700) < 0) err(1, "%s", entry->fts_path);
        } else if (entry->fts_info == FTS_DP && is_bundle(entry->fts_name)) {
            char seal[PATH_MAX], directory[PATH_MAX];
            if (snprintf(directory, sizeof(directory), "%s/Signature", entry->fts_path) >= (int)sizeof(directory) ||
                snprintf(seal, sizeof(seal), "%s/Seal", directory) >= (int)sizeof(seal)) errx(1, "seal path too long");
            if (unlink(seal) == 0) removed++;
            else if (errno != ENOENT) err(1, "%s", seal);
            if (rmdir(directory) < 0 && errno != ENOENT) err(1, "%s", directory);
        } else if (entry->fts_info != FTS_DP && entry->fts_info != FTS_F)
            errx(1, "unsupported private entry: %s", entry->fts_path);
    }
    fts_close(tree);
    return (removed);
}
static void
tree_process(const char *source, const char *output, const char *key, const char *public, bool resign)
{
    char root[PATH_MAX], *paths[2], error[256];
    struct stat st;
    unsigned count = 0, entries = 0;
    const char *input_public = public;
    if (key != NULL) {
        if (output == NULL) errx(64, "recursive signing requires -o new-directory");
        clone_tree(source, output, resign);
        if (resign) {
            /* Verify the copied generation before any signature is removed. */
            tree_process(output, NULL, NULL, public, false);
            (void)prepare_tree(output);
        }
        public = public_key(key, output);
        if (!resign) input_public = public;
        source = output;
    }
    if (lstat(source, &st) < 0 || !S_ISDIR(st.st_mode) || realpath(source, root) == NULL)
        errx(1, "a real bundle or bundle collection directory is required");
    paths[0] = root; paths[1] = NULL;
    FTS *tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (tree == NULL) err(1, "bundle traversal");
    for (;;) {
        errno = 0;
        FTSENT *entry = fts_read(tree);
        if (entry == NULL) { if (errno != 0) err(1, "bundle traversal"); break; }
        if (++entries > TREE_ENTRIES_MAX*2) errx(1, "tree entry limit exceeded");
        if (entry->fts_info != FTS_D && entry->fts_info != FTS_DP && entry->fts_info != FTS_F)
            errx(1, "symlink or unreadable entry: %s", entry->fts_path);
        if (entry->fts_info != FTS_DP || !is_bundle(entry->fts_name)) continue;
        if (key != NULL) sign_bundle(entry->fts_path, key, input_public);
        struct capbundle *bundle;
        if (capbundle_open_trusted(entry->fts_path, public, true, &bundle, error, sizeof(error)) < 0)
            errx(1, "%s: %s", entry->fts_path, error);
        if (capbundle_verify(bundle, error, sizeof(error)) < 0) errx(1, "%s: %s", entry->fts_path, error);
        printf("verified bundle %s; units=%u\n", capbundle_id(bundle), capbundle_nservices(bundle));
        capbundle_close(bundle);
        count++;
    }
    fts_close(tree);
    if (count == 0) errx(1, "no .cap bundles found");
    printf("verified bundles=%u\n", count);
}

void
capsign_tree(const char *source, const char *output, const char *key, const char *public)
{
    tree_process(source, output, key, public, false);
}
void
capsign_tree_resign(const char *source, const char *output, const char *key, const char *public)
{
    tree_process(source, output, key, public, true);
}

void
capsign_tree_remove(const char *source, const char *output)
{
    char root[PATH_MAX], *paths[2], error[256];
    unsigned removed = 0;
    clone_tree(source, output, true);
    removed = prepare_tree(output);
    if (realpath(output, root) == NULL) err(1, "%s", output);
    paths[0] = root; paths[1] = NULL;
    FTS *tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (tree == NULL) err(1, "output traversal");
    for (;;) {
        errno = 0;
        FTSENT *entry = fts_read(tree);
        if (entry == NULL) { if (errno != 0) err(1, "output traversal"); break; }
        if (entry->fts_info == FTS_F) {
            unsigned char ident[SELFMAG];
            struct stat st;
            int fd = open(entry->fts_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0 || fstat(fd, &st) < 0) err(1, "%s", entry->fts_path);
            if (pread(fd, ident, sizeof(ident), 0) != sizeof(ident) || memcmp(ident, ELFMAG, SELFMAG) != 0) { close(fd); continue; }
            if (fchmod(fd, (st.st_mode & 0777) | S_IWUSR) < 0) err(1, "writable copy");
            close(fd);
            fd = open(entry->fts_path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) err(1, "%s", entry->fts_path);
            if (capimage_remove(fd, error, sizeof(error)) == 0) removed++;
            else if (errno != ENOENT) errx(1, "%s: %s", entry->fts_path, error);
            if (fchmod(fd, st.st_mode & 0777) < 0 || fsync(fd) < 0) err(1, "finish unsigned copy");
            close(fd);
        } else if (entry->fts_info != FTS_D && entry->fts_info != FTS_DP)
            errx(1, "unsupported output entry: %s", entry->fts_path);
    }
    fts_close(tree);
    if (removed == 0) errx(1, "no signatures found");
    printf("removed signatures=%u\n", removed);
}

void
capsign_tree_preview(const char *source, const char *output, const char *key,
    const char *public, bool resign)
{
    char root[PATH_MAX], parent[PATH_MAX], destination[PATH_MAX];
    const char *leaf, *temporary = getenv("TMPDIR");
    struct stat st;
    if (realpath(source, root) == NULL) err(1, "%s", source);
    leaf = strrchr(root, '/') + 1;
    if (output != NULL) {
        if (lstat(output, &st) == 0 || errno != ENOENT)
            errx(1, "dry-run output must be a new path");
        if (strlcpy(parent, output, sizeof(parent)) >= sizeof(parent))
            errx(1, "output path too long");
        char *slash = strrchr(parent, '/');
        leaf = strrchr(output, '/');
        leaf = leaf == NULL ? output : leaf + 1;
        if (slash != NULL) {
            *slash = 0;
            temporary = parent[0] == 0 ? "/" : parent;
        } else temporary = ".";
    } else if (temporary == NULL || temporary[0] == 0) temporary = "/tmp";
    if (leaf[0] == 0 || strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0)
        errx(1, "invalid dry-run output name");
    if (asprintf(&preview_directory, "%s/.capsign-preview.XXXXXX", temporary) < 0)
        err(1, "dry-run path");
    if (mkdtemp(preview_directory) == NULL) err(1, "dry-run directory");
    atexit(cleanup_preview);
    if (snprintf(destination, sizeof(destination), "%s/%s", preview_directory, leaf) >= (int)sizeof(destination))
        errx(1, "dry-run destination too long");
    tree_process(source, destination, key, public, resign);
    if (remove_preview() < 0) errx(1, "dry-run cleanup failed: %s", preview_directory);
    puts("dry-run: no signed tree published");
}
