/*-
 * Copyright (c) 2023-2025 Dag-Erling Smørgrav <des@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/tree.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <paths.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define info(fmt, ...)							\
	do {								\
		if (verbose)						\
			fprintf(stderr, fmt "\n", ##__VA_ARGS__);	\
	} while (0)

static char *
xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *str;
	int ret;

	va_start(ap, fmt);
	ret = vasprintf(&str, fmt, ap);
	va_end(ap);
	if (ret < 0 || str == NULL)
		err(1, NULL);
	return (str);
}

static char *
xstrdup(const char *str)
{
	char *dup;

	if ((dup = strdup(str)) == NULL)
		err(1, NULL);
	return (dup);
}

static void usage(void);

static bool dryrun;
static bool longnames;
static bool nobundle;
static bool unprivileged;
static bool verbose;
static bool explicit_files;

static const char *localbase;
static const char *destdir;
static const char *distbase;
static const char *metalog;

static const char *uname = "root";
static const char *gname = "wheel";

static const char *const default_trusted_paths[] = {
	"/usr/share/certs/trusted",
	"%L/share/certs/trusted",
	"%L/share/certs",
	NULL
};
static char **trusted_paths;
static bool trusted_paths_explicit;

static const char *const default_untrusted_paths[] = {
	"/usr/share/certs/untrusted",
	"%L/share/certs/untrusted",
	NULL
};
static char **untrusted_paths;
static bool untrusted_paths_explicit;

static char *trusted_dest;
static char *untrusted_dest;
static char *bundle_dest;
static const char *trusted_output;
static const char *untrusted_output;
static const char *bundle_output;

#define SSL_PATH		"/etc/ssl"
#define TRUSTED_DIR		"certs"
#define TRUSTED_PATH		SSL_PATH "/" TRUSTED_DIR
#define UNTRUSTED_DIR		"untrusted"
#define UNTRUSTED_PATH		SSL_PATH "/" UNTRUSTED_DIR
#define LEGACY_DIR		"blacklisted"
#define LEGACY_PATH		SSL_PATH "/" LEGACY_DIR
#define BUNDLE_FILE		"cert.pem"
#define BUNDLE_PATH		SSL_PATH "/" BUNDLE_FILE

static FILE *mlf;

/*
 * Create a directory and its parents as needed.
 */
static void
mkdirp(const char *dir)
{
	struct stat sb;
	const char *sep;
	char *parent;

	if (dryrun)
		return;
	if (stat(dir, &sb) == 0) {
		if (!S_ISDIR(sb.st_mode))
			errx(1, "%s: not a directory", dir);
		return;
	}
	if (errno != ENOENT)
		err(1, "%s", dir);
	if ((sep = strrchr(dir, '/')) != NULL) {
		parent = xasprintf("%.*s", (int)(sep - dir), dir);
		mkdirp(parent);
		free(parent);
	}
	info("creating %s", dir);
	if (mkdir(dir, 0755) != 0)
		err(1, "mkdir %s", dir);
}

/*
 * Remove duplicate and trailing slashes from a path.
 */
static char *
normalize_path(const char *str)
{
	char *buf, *dst;

	if ((buf = malloc(strlen(str) + 1)) == NULL)
		err(1, NULL);
	for (dst = buf; *str != '\0'; dst++) {
		if ((*dst = *str++) == '/') {
			while (*str == '/')
				str++;
			if (*str == '\0')
				break;
		}
	}
	*dst = '\0';
	return (buf);
}

/*
 * Split a colon-separated list into a NULL-terminated array.
 */
static char **
split_paths(const char *str)
{
	char **paths;
	const char *p, *q;
	unsigned int i, n;

	for (p = str, n = 1; *p; p++) {
		if (*p == ':')
			n++;
	}
	if ((paths = calloc(n + 1, sizeof(*paths))) == NULL)
		err(1, NULL);
	if (*str == '\0')
		return (paths);
	for (p = q = str, i = 0; i < n; i++, p = q + 1) {
		q = strchrnul(p, ':');
		if (q == p)
			errx(1, "empty component in certificate search path");
		if ((paths[i] = strndup(p, q - p)) == NULL)
			err(1, NULL);
	}
	return (paths);
}

/* Append an explicitly selected certificate file, preserving argument order. */
static void
append_path(char ***paths, const char *path)
{
	char **newpaths;
	size_t n;

	if (*path == '\0')
		errx(1, "empty certificate input path");
	for (n = 0; *paths != NULL && (*paths)[n] != NULL; n++)
		continue;
	newpaths = reallocarray(*paths, n + 2, sizeof(*newpaths));
	if (newpaths == NULL)
		err(1, NULL);
	newpaths[n] = xstrdup(path);
	newpaths[n + 1] = NULL;
	*paths = newpaths;
}

/*
 * Expand %L into LOCALBASE and prefix DESTDIR and DISTBASE as needed.
 */
static char *
expand_path(const char *template)
{
	if (template[0] == '%' && template[1] == 'L')
		return (xasprintf("%s%s%s", destdir, localbase, template + 2));
	return (xasprintf("%s%s%s", destdir, distbase, template));
}

/*
 * Expand an array of paths.
 */
static char **
expand_paths(const char *const *templates)
{
	char **paths;
	unsigned int i, n;

	for (n = 0; templates[n] != NULL; n++)
		continue;
	if ((paths = calloc(n + 1, sizeof(*paths))) == NULL)
		err(1, NULL);
	for (i = 0; i < n; i++)
		paths[i] = expand_path(templates[i]);
	return (paths);
}

/*
 * If destdir is a prefix of path, returns a pointer to the rest of path,
 * otherwise returns path.
 *
 * Note that this intentionally does not strip distbase from the path!
 * Unlike destdir, distbase is expected to be included in the metalog.
 */
static const char *
unexpand_path(const char *path)
{
	const char *p = path;
	const char *q = destdir;

	while (*p && *p == *q) {
		p++;
		q++;
	}
	return (*q == '\0' && *p == '/' ? p : path);
}

/*
 * X509 certificate in a rank-balanced tree.
 */
struct cert {
	RB_ENTRY(cert) entry;
	unsigned long hash;
	char *name;
	X509 *x509;
	char *path;
};

static void
free_cert(struct cert *cert)
{
	free(cert->name);
	X509_free(cert->x509);
	free(cert->path);
	free(cert);
}

static int
certcmp(const struct cert *a, const struct cert *b)
{
	return (X509_cmp(a->x509, b->x509));
}

RB_HEAD(cert_tree, cert);
static struct cert_tree trusted = RB_INITIALIZER(&trusted);
static struct cert_tree untrusted = RB_INITIALIZER(&untrusted);
RB_GENERATE_STATIC(cert_tree, cert, entry, certcmp);

static void
free_certs(struct cert_tree *tree)
{
	struct cert *cert, *tmp;

	RB_FOREACH_SAFE(cert, cert_tree, tree, tmp) {
		RB_REMOVE(cert_tree, tree, cert);
		free_cert(cert);
	}
}

static struct cert *
find_cert(struct cert_tree *haystack, X509 *x509)
{
	struct cert needle = { .x509 = x509 };

	return (RB_FIND(cert_tree, haystack, &needle));
}

/*
 * File containing a certificate in a rank-balanced tree sorted by
 * certificate hash and disambiguating counter.  This is needed because
 * the certificate hash function is prone to collisions, necessitating a
 * counter to distinguish certificates that hash to the same value.
 */
struct file {
	RB_ENTRY(file) entry;
	const struct cert *cert;
	unsigned int c;
};

static int
filecmp(const struct file *a, const struct file *b)
{
	if (a->cert->hash > b->cert->hash)
		return (1);
	if (a->cert->hash < b->cert->hash)
		return (-1);
	return (a->c - b->c);
}

RB_HEAD(file_tree, file);
RB_GENERATE_STATIC(file_tree, file, entry, filecmp);

/*
 * Lexicographical sort for scandir().
 */
static int
lexisort(const struct dirent **d1, const struct dirent **d2)
{
	return (strcmp((*d1)->d_name, (*d2)->d_name));
}

/*
 * Read certificate(s) from a single file and insert them into a tree.
 * Ignore certificates that already exist in the tree.  If exclude is not
 * null, also ignore certificates that exist in exclude.
 *
 * Returns the number certificates added to the tree, or -1 on failure.
 */
static int
read_cert(const char *path, struct cert_tree *tree, struct cert_tree *exclude)
{
	struct stat sb;
	FILE *f;
	X509 *x509;
	X509_NAME *name;
	struct cert *cert;
	unsigned long hash, error;
	int fd, len, ni, no, ok, ret = 0;

	/* Do not block on an explicitly supplied FIFO or read a device. */
	if ((fd = open(path, O_RDONLY | O_NONBLOCK)) < 0) {
		warn("%s", path);
		return (-1);
	}
	if (fstat(fd, &sb) != 0) {
		warn("%s", path);
		close(fd);
		return (-1);
	}
	if (!S_ISREG(sb.st_mode)) {
		warnx("%s: not a regular certificate file", path);
		close(fd);
		return (-1);
	}
	if ((f = fdopen(fd, "r")) == NULL) {
		warn("%s", path);
		close(fd);
		return (-1);
	}
	for (ni = no = 0;; ni++) {
		ERR_clear_error();
		x509 = PEM_read_X509(f, NULL, NULL, NULL);
		if (x509 == NULL) {
			error = ERR_peek_last_error();
			if (ferror(f) || !feof(f) || (error != 0 &&
			    (ERR_GET_LIB(error) != ERR_LIB_PEM ||
			    ERR_GET_REASON(error) != PEM_R_NO_START_LINE))) {
				warnx("%s: certificate read failed: %s", path,
				    error ? ERR_error_string(error, NULL) :
				    "input error");
				ret = -1;
			}
			break;
		}
		name = X509_get_subject_name(x509);
		hash = X509_NAME_hash_ex(name, NULL, NULL, &ok);
		if (!ok) {
			warnx("%s: cannot hash certificate subject", path);
			X509_free(x509);
			ret = -1;
			break;
		}
		if (exclude && find_cert(exclude, x509)) {
			info("%08lx: excluded", hash);
			X509_free(x509);
			continue;
		}
		if (find_cert(tree, x509)) {
			info("%08lx: duplicate", hash);
			X509_free(x509);
			continue;
		}
		if ((cert = calloc(1, sizeof(*cert))) == NULL)
			err(1, NULL);
		cert->x509 = x509;
		cert->hash = hash;
		len = X509_NAME_get_text_by_NID(name, NID_commonName,
		    NULL, 0);
		if (len > 0) {
			if ((cert->name = malloc(len + 1)) == NULL)
				err(1, NULL);
			X509_NAME_get_text_by_NID(name, NID_commonName,
			    cert->name, len + 1);
		} else {
			/* fallback for certificates without CN */
			cert->name = X509_NAME_oneline(name, NULL, 0);
		}
		cert->path = xstrdup(unexpand_path(path));
		if (RB_INSERT(cert_tree, tree, cert) != NULL)
			errx(1, "unexpected duplicate");
		info("%08lx: %s", cert->hash, cert->name);
		no++;
	}
	/*
	 * ni is the number of certificates we found in the file.
	 * no is the number of certificates that weren't already in our
	 * tree or on the exclusion list.
	 */
	if (ni == 0) {
		warnx("%s: no valid certificates found", path);
		ret = -1;
	}
	if (fclose(f) != 0) {
		warn("%s", path);
		ret = -1;
	}
	return (ret == 0 ? no : -1);
}

/*
 * Load all certificates found in the specified path into a tree,
 * optionally excluding those that already exist in a different tree.
 *
 * Returns the number of certificates added to the tree, or -1 on failure.
 */
static int
read_certs(const char *path, struct cert_tree *tree, struct cert_tree *exclude,
    bool optional)
{
	struct stat sb;
	char *paths[] = { __DECONST(char *, path), NULL };
	FTS *fts;
	FTSENT *ent;
	int ret, total = 0;
	bool failed = false;

	if (stat(path, &sb) != 0) {
		/* A dangling symlink is not an absent optional directory. */
		if (optional && errno == ENOENT && lstat(path, &sb) != 0 &&
		    errno == ENOENT)
			return (0);
		warn("%s", path);
		return (-1);
	}
	if (!S_ISDIR(sb.st_mode)) {
		warnx("%s: not a directory", path);
		return (-1);
	}
	if ((fts = fts_open(paths, FTS_LOGICAL | FTS_NOCHDIR, NULL)) == NULL) {
		warn("%s", path);
		return (-1);
	}
	for (;;) {
		errno = 0;
		if ((ent = fts_read(fts)) == NULL) {
			if (errno != 0) {
				warn("fts_read %s", path);
				failed = true;
			}
			break;
		}
		switch (ent->fts_info) {
		case FTS_D:
		case FTS_DP:
			break;
		case FTS_F:
			info("found %s", ent->fts_path);
			ret = read_cert(ent->fts_path, tree, exclude);
			if (ret < 0)
				failed = true;
			else
				total += ret;
			break;
		default:
			if (ent->fts_errno != 0)
				warnc(ent->fts_errno, "%s", ent->fts_path);
			else
				warnx("%s: invalid certificate input", ent->fts_path);
			failed = true;
			break;
		}
	}
	if (fts_close(fts) != 0) {
		warn("fts_close %s", path);
		failed = true;
	}
	return (failed ? -1 : total);
}

/* Open a new temporary output without following an existing link. */
static FILE *
open_output(int d, const char *tmp, mode_t mode, char **buffer, size_t *size)
{
	FILE *f;
	int fd, saved;

	*buffer = NULL;
	*size = 0;
	/* Encode dry-run output in memory, retaining its real byte count. */
	if (dryrun)
		return (open_memstream(buffer, size));
	fd = openat(d, tmp, O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY, mode);
	if (fd < 0)
		return (NULL);
	if (!dryrun && !unprivileged && fchmod(fd, mode) != 0)
		goto fail;
	if ((f = fdopen(fd, "w")) != NULL)
		return (f);
fail:
	saved = errno;
	close(fd);
	if (!dryrun)
		(void)unlinkat(d, tmp, 0);
	errno = saved;
	return (NULL);
}

/* Detect buffered write and close errors before replacing a usable file. */
static int
finish_output(FILE *f, int d, const char *dir, const char *tmp,
    const char *path, mode_t mode, int ret)
{
	long size = 0;

	if (fflush(f) != 0 || ferror(f)) {
		warn("flush %s/%s", dir, tmp);
		ret = -1;
	}
	if (ret == 0 && (size = ftell(f)) < 0) {
		warn("ftell %s/%s", dir, tmp);
		ret = -1;
	}
	if (fclose(f) != 0) {
		warn("close %s/%s", dir, tmp);
		ret = -1;
	}
	if (!dryrun) {
		if (ret == 0 && renameat(d, tmp, d, path) != 0) {
			warn("rename %s/%s", dir, path);
			ret = -1;
		}
		if (ret != 0 && unlinkat(d, tmp, 0) != 0)
			warn("unlink %s/%s", dir, tmp);
	}
	if (ret == 0 && mlf != NULL && fprintf(mlf,
	    ".%s/%s type=file uname=%s gname=%s mode=%#o size=%ld\n",
	    unexpand_path(dir), path, uname, gname, mode, size) < 0) {
		warn("%s", metalog);
		ret = -1;
	}
	return (ret);
}

/*
 * Save the contents of a cert tree to disk.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
write_certs(const char *dir, struct cert_tree *tree)
{
	struct file_tree files = RB_INITIALIZER(&files);
	struct cert *cert;
	struct file *file, *tmp;
	struct dirent **dents, **ent;
	char *path, *tmppath = NULL, *buffer;
	size_t size;
	FILE *f;
	mode_t mode = 0444;
	int cmp, d, ndents, ret = 0;

	/*
	 * Start by generating unambiguous file names for each certificate
	 * and storing them in lexicographical order
	 */
	RB_FOREACH(cert, cert_tree, tree) {
		if ((file = calloc(1, sizeof(*file))) == NULL)
			err(1, NULL);
		file->cert = cert;
		for (file->c = 0; file->c < INT_MAX; file->c++)
			if (RB_INSERT(file_tree, &files, file) == NULL)
				break;
		if (file->c == INT_MAX)
			errx(1, "unable to disambiguate %08lx", cert->hash);
		free(cert->path);
		cert->path = xasprintf("%08lx.%d", cert->hash, file->c);
	}
	/*
	 * Open and scan the directory.
	 */
	d = open(dir, O_DIRECTORY | O_RDONLY);
	if (d < 0 && dryrun && errno == ENOENT) {
		ndents = 0;
		if ((dents = calloc(1, sizeof(*dents))) == NULL)
			err(1, NULL);
	} else {
		if (d < 0)
			err(1, "%s", dir);
#ifdef BOOTSTRAPPING
		ndents = scandir(dir, &dents, NULL, lexisort);
#else
		ndents = fdscandir(d, &dents, NULL, lexisort);
#endif
		if (ndents < 0)
			err(1, "%s", dir);
	}
	/*
	 * Iterate over the directory listing and the certificate listing
	 * in parallel.  If the directory listing gets ahead of the
	 * certificate listing, we need to write the current certificate
	 * and advance the certificate listing.  If the certificate
	 * listing is ahead of the directory listing, we need to delete
	 * the current file and advance the directory listing.  If they
	 * are neck and neck, we have a match and could in theory compare
	 * the two, but in practice it's faster to just replace the
	 * current file with the current certificate (and advance both).
	 */
	ent = dents;
	file = RB_MIN(file_tree, &files);
	for (;;) {
		if (ent < dents + ndents) {
			/* skip directories */
			if ((*ent)->d_type == DT_DIR) {
				free(*ent++);
				continue;
			}
			if (file != NULL) {
				/* compare current dirent to current cert */
				path = file->cert->path;
				cmp = strcmp((*ent)->d_name, path);
			} else {
				/* trailing files in directory */
				path = NULL;
				cmp = -1;
			}
		} else {
			if (file != NULL) {
				/* trailing certificates */
				path = file->cert->path;
				cmp = 1;
			} else {
				/* end of both lists */
				path = NULL;
				break;
			}
		}
		if (cmp < 0) {
			/* a file on disk with no matching certificate */
			info("removing %s/%s", dir, (*ent)->d_name);
			if (!dryrun && unlinkat(d, (*ent)->d_name, 0) != 0) {
				warn("unlink %s/%s", dir, (*ent)->d_name);
				ret = -1;
				break;
			}
			free(*ent++);
			continue;
		}
		if (cmp == 0)
			free(*ent++);
		info("writing %s/%s", dir, path);
		tmppath = xasprintf(".%s", path);
		f = open_output(d, tmppath, mode, &buffer, &size);
		if (f == NULL) {
			warn("%s/%s", dir, tmppath);
			ret = -1;
		} else {
			if (!PEM_write_X509(f, file->cert->x509)) {
				warnx("%s/%s: certificate write failed", dir, tmppath);
				ret = -1;
			}
			ret = finish_output(f, d, dir, tmppath, path, mode, ret);
		}
		free(buffer);
		free(tmppath);
		tmppath = NULL;
		if (ret != 0)
			break;
		/* advance certificate listing */
		tmp = RB_NEXT(file_tree, &files, file);
		RB_REMOVE(file_tree, &files, file);
		free(file);
		file = tmp;
	}
	while (ent < dents + ndents)
		free(*ent++);
	free(dents);
	RB_FOREACH_SAFE(file, file_tree, &files, tmp) {
		RB_REMOVE(file_tree, &files, file);
		free(file);
	}
	if (d >= 0)
		close(d);
	return (ret);
}

/*
 * Save all certs in a tree to a single file (bundle).
 *
 * Returns 0 on success and -1 on failure.
 */
static int
write_bundle(const char *dir, const char *file, struct cert_tree *tree)
{
	struct cert *cert;
	char *tmpfile, *buffer;
	size_t size;
	FILE *f;
	int d, ret = 0;
	mode_t mode = 0444;

	if (dir != NULL) {
		d = open(dir, O_DIRECTORY | O_RDONLY);
		if (d < 0 && !(dryrun && errno == ENOENT))
			err(1, "%s", dir);
	} else {
		dir = ".";
		d = AT_FDCWD;
	}
	info("writing %s/%s", dir, file);
	tmpfile = xasprintf(".%s", file);
	if ((f = open_output(d, tmpfile, mode, &buffer, &size)) == NULL) {
		warn("%s/%s", dir, tmpfile);
		ret = -1;
	} else {
		RB_FOREACH(cert, cert_tree, tree) {
			if (!PEM_write_X509(f, cert->x509)) {
				warnx("%s/%s: certificate write failed", dir, tmpfile);
				ret = -1;
				break;
			}
		}
		ret = finish_output(f, d, dir, tmpfile, file, mode, ret);
	}
	free(buffer);
	free(tmpfile);
	if (d >= 0)
		close(d);
	return (ret);
}

/*
 * Load trusted certificates.
 *
 * Returns the number of certificates loaded.
 */
static int
load_trusted(void)
{
	unsigned int i, n;
	int ret;

	/* load external trusted certs */
	for (i = n = 0; trusted_paths[i] != NULL; i++) {
		ret = explicit_files ?
		    read_cert(trusted_paths[i], &trusted, &untrusted) :
		    read_certs(trusted_paths[i], &trusted, &untrusted,
		    !trusted_paths_explicit);
		if (ret < 0)
			return (-1);
		if (ret > 0)
			n += ret;
	}

	info("%d trusted certificates found", n);
	return (n);
}

/*
 * Load untrusted certificates.
 *
 * Returns the number of certificates loaded.
 */
static int
load_untrusted(void)
{
	char *path;
	unsigned int i, n;
	int ret;

	/* load external untrusted certs */
	for (i = n = 0; untrusted_paths[i] != NULL; i++) {
		ret = explicit_files ?
		    read_cert(untrusted_paths[i], &untrusted, NULL) :
		    read_certs(untrusted_paths[i], &untrusted, NULL,
		    !untrusted_paths_explicit);
		if (ret < 0)
			return (-1);
		if (ret > 0)
			n += ret;
	}

	/* Explicit selection has no legacy or directory-discovery inputs. */
	if (explicit_files)
		return (n);
	/* load legacy untrusted certs */
	path = expand_path(LEGACY_PATH);
	ret = read_certs(path, &untrusted, NULL, true);
	if (ret > 0) {
		warnx("certificates found in legacy directory %s",
		    path);
		n += ret;
	}
	free(path);
	if (ret < 0)
		return (-1);

	info("%d untrusted certificates found", n);
	return (n);
}

/*
 * Save trusted certificates.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
save_trusted(void)
{
	int ret;

	mkdirp(trusted_dest);
	ret = write_certs(trusted_dest, &trusted);
	return (ret);
}

/*
 * Save untrusted certificates.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
save_untrusted(void)
{
	int ret;

	mkdirp(untrusted_dest);
	ret = write_certs(untrusted_dest, &untrusted);
	return (ret);
}

/*
 * Save certificate bundle.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
save_bundle(void)
{
	char *dir, *file, *sep;
	int ret;

	if ((sep = strrchr(bundle_dest, '/')) == NULL) {
		dir = NULL;
		file = bundle_dest;
	} else {
		dir = sep == bundle_dest ? xstrdup("/") :
		    xasprintf("%.*s", (int)(sep - bundle_dest), bundle_dest);
		file = sep + 1;
		mkdirp(dir);
	}
	ret = write_bundle(dir, file, &trusted);
	free(dir);
	return (ret);
}

/*
 * Save everything.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
save_all(void)
{
	int ret = 0;

	if ((ret = save_untrusted()) != 0 || (ret = save_trusted()) != 0)
		return (ret);
	if (!nobundle)
		ret |= save_bundle();
	return (ret);
}

/*
 * List the contents of a certificate tree.
 */
static void
list_certs(struct cert_tree *tree)
{
	struct cert *cert;
	char *path, *name;

	RB_FOREACH(cert, cert_tree, tree) {
		path = longnames ? NULL : strrchr(cert->path, '/');
		name = longnames ? NULL : strrchr(cert->name, '=');
		printf("%s\t%s\n", path ? path + 1 : cert->path,
		    name ? name + 1 : cert->name);
	}
}

/*
 * Load installed trusted certificates, then list them.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
certctl_list(int argc, char **argv __unused)
{
	if (argc > 1)
		usage();
	/* load installed trusted certificates */
	if (read_certs(trusted_dest, &trusted, NULL, false) < 0) {
		free_certs(&trusted);
		return (-1);
	}
	/* list them */
	list_certs(&trusted);
	free_certs(&trusted);
	return (0);
}

/*
 * Load installed untrusted certificates, then list them.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
certctl_untrusted(int argc, char **argv __unused)
{
	if (argc > 1)
		usage();
	/* load installed untrusted certificates */
	if (read_certs(untrusted_dest, &untrusted, NULL, false) < 0) {
		free_certs(&untrusted);
		return (-1);
	}
	/* list them */
	list_certs(&untrusted);
	free_certs(&untrusted);
	return (0);
}

/*
 * Load trusted and untrusted certificates from all sources, then
 * regenerate both the hashed directories and the bundle.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
certctl_rehash(int argc, char **argv __unused)
{
	int ret;

	if (argc > 1)
		usage();

	/* All inputs must be accepted before touching installed outputs. */
	if (load_untrusted() < 0 || load_trusted() < 0) {
		free_certs(&untrusted);
		free_certs(&trusted);
		return (-1);
	}

	if (unprivileged)
		mlf = strcmp(metalog, "-") == 0 ? stdout : fopen(metalog, "a");
	if (unprivileged && mlf == NULL) {
		warn("%s", metalog);
		free_certs(&untrusted);
		free_certs(&trusted);
		return (-1);
	}

	/* save everything */
	ret = save_all();

	/* clean up */
	free_certs(&untrusted);
	free_certs(&trusted);
	if (mlf != NULL) {
		if (fclose(mlf) != 0) {
			warn("%s", metalog);
			ret = -1;
		}
		mlf = NULL;
	}
	return (ret);
}

/*
 * Manually add one or more certificates to the list of trusted
 * certificates.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
certctl_trust(int argc, char **argv)
{
	struct cert_tree extra = RB_INITIALIZER(&extra);
	struct cert *cert, *other, *tmp;
	unsigned int n;
	int i, ret;

	if (argc < 2)
		usage();

	/* All inputs must be accepted before touching installed outputs. */
	if (load_untrusted() < 0 || load_trusted() < 0) {
		free_certs(&untrusted);
		free_certs(&trusted);
		return (-1);
	}

	/* now load the additional trusted certificates */
	n = 0;
	for (i = 1; i < argc; i++) {
		ret = read_cert(argv[i], &extra, &trusted);
		if (ret < 0) {
			free_certs(&extra);
			free_certs(&untrusted);
			free_certs(&trusted);
			return (-1);
		}
		if (ret > 0)
			n += ret;
	}
	if (n == 0) {
		warnx("no new trusted certificates found");
		free_certs(&untrusted);
		free_certs(&trusted);
		return (0);
	}
	warnx("%u new trusted certificate%s found", n, n > 1 ? "s" : "");

	/*
	 * For each new trusted cert, move it from the extra list to the
	 * trusted list, then check if a matching certificate exists on
	 * the untrusted list.  If that is the case, warn the user, then
	 * remove the matching certificate from the untrusted list.
	 */
	RB_FOREACH_SAFE(cert, cert_tree, &extra, tmp) {
		RB_REMOVE(cert_tree, &extra, cert);
		RB_INSERT(cert_tree, &trusted, cert);
		if ((other = RB_FIND(cert_tree, &untrusted, cert)) != NULL) {
			warnx("%s was previously untrusted", cert->name);
			warnx("source of untrust: %s", other->path);
			RB_REMOVE(cert_tree, &untrusted, other);
			free_cert(other);
		}
	}
	warnx("This operation is not persistent.  To persistently add");
	warnx("trusted certificates to the system store, copy them to");
	warnx("one of these directories, then run `certctl rehash`:");
	for (i = 0; trusted_paths[i] != NULL; i++)
		warnx("    %s", trusted_paths[i]);

	/* save everything */
	ret = save_all();

	/* clean up */
	free_certs(&untrusted);
	free_certs(&trusted);
	return (ret);
}

/*
 * Manually add one or more certificates to the list of untrusted
 * certificates.
 *
 * Returns 0 on success and -1 on failure.
 */
static int
certctl_untrust(int argc, char **argv)
{
	struct cert_tree extra = RB_INITIALIZER(&extra);
	struct cert *cert, *other, *tmp;
	unsigned int n;
	int i, ret;

	if (argc < 2)
		usage();

	/* All inputs must be accepted before touching installed outputs. */
	if (load_untrusted() < 0 || load_trusted() < 0) {
		free_certs(&untrusted);
		free_certs(&trusted);
		return (-1);
	}

	/* now load the additional untrusted certificates */
	n = 0;
	for (i = 1; i < argc; i++) {
		ret = read_cert(argv[i], &extra, NULL);
		if (ret < 0) {
			free_certs(&extra);
			free_certs(&untrusted);
			free_certs(&trusted);
			return (-1);
		}
		if (ret > 0)
			n += ret;
	}
	if (n == 0) {
		warnx("no new untrusted certificates found");
		free_certs(&untrusted);
		free_certs(&trusted);
		return (0);
	}
	warnx("%u new untrusted certificate%s found", n, n > 1 ? "s" : "");

	/*
	 * For each new untrusted cert, move it from the extra list to the
	 * untrusted list, then check if a matching certificate exists on
	 * the trusted list.  If that is the case, warn the user, then
	 * remove the matching certificate from the trusted list.
	 */
	RB_FOREACH_SAFE(cert, cert_tree, &extra, tmp) {
		RB_REMOVE(cert_tree, &extra, cert);
		RB_INSERT(cert_tree, &untrusted, cert);
		if ((other = RB_FIND(cert_tree, &trusted, cert)) != NULL) {
			warnx("%s was previously trusted", cert->name);
			warnx("source of trust: %s", other->path);
			RB_REMOVE(cert_tree, &trusted, other);
			free_cert(other);
		}
	}
	warnx("This operation is not persistent.  To persistently add");
	warnx("untrusted certificates to the system store, copy them to");
	warnx("one of these directories, then run `certctl rehash`:");
	for (i = 0; untrusted_paths[i] != NULL; i++)
		warnx("    %s", untrusted_paths[i]);

	/* save everything */
	ret = save_all();

	/* clean up */
	free_certs(&untrusted);
	free_certs(&trusted);
	return (ret);
}

static void
set_defaults(void)
{
	const char *value;
	char *str;
	size_t len;

	/* LOCALBASE is used only by directory discovery. */
	if (explicit_files && localbase == NULL)
		localbase = "";
	if (localbase == NULL &&
	    (localbase = getenv("LOCALBASE")) == NULL) {
		if ((str = malloc((len = PATH_MAX) + 1)) == NULL)
			err(1, NULL);
		while (sysctlbyname("user.localbase", str, &len, NULL, 0) < 0) {
			if (errno != ENOMEM)
				err(1, "sysctl(user.localbase)");
			if ((str = realloc(str, len + 1)) == NULL)
				err(1, NULL);
		}
		str[len] = '\0';
		localbase = str;
	}

	if (destdir == NULL &&
	    (destdir = getenv("DESTDIR")) == NULL)
		destdir = "";
	destdir = normalize_path(destdir);

	if (distbase == NULL &&
	    (distbase = getenv("DISTBASE")) == NULL)
		distbase = "";
	if (*distbase != '\0' && *distbase != '/')
		errx(1, "DISTBASE=%s does not begin with a slash", distbase);
	distbase = normalize_path(distbase);

	if (unprivileged && metalog == NULL &&
	    (metalog = getenv("METALOG")) == NULL)
		metalog = xasprintf("%s/METALOG", destdir);

	if (!verbose) {
		if ((value = getenv("CERTCTL_VERBOSE")) != NULL) {
			if (value[0] != '\0') {
				verbose = true;
			}
		}
	}

	if (explicit_files) {
		if (trusted_paths == NULL &&
		    (trusted_paths = calloc(1, sizeof(*trusted_paths))) == NULL)
			err(1, NULL);
	} else if ((value = getenv("TRUSTPATH")) != NULL) {
		trusted_paths_explicit = true;
		trusted_paths = split_paths(value);
	} else
		trusted_paths = expand_paths(default_trusted_paths);

	if (explicit_files) {
		if (untrusted_paths == NULL &&
		    (untrusted_paths = calloc(1, sizeof(*untrusted_paths))) == NULL)
			err(1, NULL);
	} else if ((value = getenv("UNTRUSTPATH")) != NULL) {
		untrusted_paths_explicit = true;
		untrusted_paths = split_paths(value);
	} else
		untrusted_paths = expand_paths(default_untrusted_paths);

	if (trusted_output != NULL)
		trusted_dest = normalize_path(trusted_output);
	else if ((value = getenv("TRUSTDESTDIR")) != NULL ||
	    (value = getenv("CERTDESTDIR")) != NULL)
		trusted_dest = normalize_path(value);
	else
		trusted_dest = expand_path(TRUSTED_PATH);

	if (untrusted_output != NULL)
		untrusted_dest = normalize_path(untrusted_output);
	else if ((value = getenv("UNTRUSTDESTDIR")) != NULL)
		untrusted_dest = normalize_path(value);
	else
		untrusted_dest = expand_path(UNTRUSTED_PATH);

	if (bundle_output != NULL)
		bundle_dest = normalize_path(bundle_output);
	else if ((value = getenv("BUNDLE")) != NULL)
		bundle_dest = normalize_path(value);
	else
		bundle_dest = expand_path(BUNDLE_PATH);

	info("localbase:\t%s", localbase);
	info("destdir:\t%s", destdir);
	info("distbase:\t%s", distbase);
	info("unprivileged:\t%s", unprivileged ? "true" : "false");
	info("verbose:\t%s", verbose ? "true" : "false");
}

typedef int (*main_t)(int, char **);

static struct {
	const char	*name;
	main_t		 func;
} commands[] = {
	{ "list",	certctl_list },
	{ "untrusted",	certctl_untrusted },
	{ "rehash",	certctl_rehash },
	{ "untrust",	certctl_untrust },
	{ "trust",	certctl_trust },
	{ 0 },
};

static void
usage(void)
{
	fprintf(stderr, "usage: certctl [-lv] [-D destdir] [-d distbase] list\n"
	    "       certctl [-lv] [-D destdir] [-d distbase] untrusted\n"
	    "       certctl [-BnUv] [-D destdir] [-d distbase] [-M metalog] rehash\n"
	    "       certctl -E [-BnUv] [-T file] [-X file] [-C trusted-dir]\n"
	    "               [-R untrusted-dir] [-b bundle] [-D destdir] [-M metalog] rehash\n"
	    "       certctl [-nv] [-D destdir] [-d distbase] untrust <file>\n"
	    "       certctl [-nv] [-D destdir] [-d distbase] trust <file>\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *command;
	unsigned int i;
	int opt;

	while ((opt = getopt(argc, argv, "Bb:C:cD:d:Eg:lL:M:no:R:T:UvX:")) != -1)
		switch (opt) {
		case 'B':
			nobundle = true;
			break;
		case 'b':
			bundle_output = optarg;
			break;
		case 'C':
			trusted_output = optarg;
			break;
		case 'R':
			untrusted_output = optarg;
			break;
		case 'c':
			/* ignored for compatibility */
			break;
		case 'D':
			destdir = optarg;
			break;
		case 'd':
			distbase = optarg;
			break;
		case 'E':
			explicit_files = true;
			break;
		case 'g':
			gname = optarg;
			break;
		case 'l':
			longnames = true;
			break;
		case 'L':
			localbase = optarg;
			break;
		case 'M':
			metalog = optarg;
			break;
		case 'n':
			dryrun = true;
			break;
		case 'o':
			uname = optarg;
			break;
		case 'U':
			unprivileged = true;
			break;
		case 'T':
			append_path(&trusted_paths, optarg);
			break;
		case 'X':
			append_path(&untrusted_paths, optarg);
			break;
		case 'v':
			verbose = true;
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	command = *argv;

	if (!explicit_files && (trusted_paths != NULL || untrusted_paths != NULL ||
	    trusted_output != NULL || untrusted_output != NULL || bundle_output != NULL)) {
		warnx("-T, -X, -C, -R and -b require -E");
		usage();
	}
	if ((trusted_output != NULL && *trusted_output == '\0') ||
	    (untrusted_output != NULL && *untrusted_output == '\0') ||
	    (bundle_output != NULL && *bundle_output == '\0'))
		errx(1, "empty certificate output path");
	if ((explicit_files || nobundle || unprivileged || metalog != NULL) &&
	    strcmp(command, "rehash") != 0)
		usage();
	if (!unprivileged && metalog != NULL) {
		warnx("-M may only be used in conjunction with -U");
		usage();
	}

	set_defaults();

	for (i = 0; commands[i].name != NULL; i++)
		if (strcmp(command, commands[i].name) == 0)
			exit(commands[i].func(argc, argv) == 0 ? 0 : 1);
	usage();
}
