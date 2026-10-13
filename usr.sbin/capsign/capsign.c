/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include "capsign_tree.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <capimage.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <libcapbundle.h>

static char *temporary;
static void
cleanup_temporary(void)
{
	if (temporary != NULL)
		unlink(temporary);
}
static void
usage(void)
{
	fprintf(stderr, "usage: capsign key-id -p public.pem\n"
	    "       capsign note -m policy.ucl -o note.S\n"
	    "       capsign validate-policy policy.ucl\n"
	    "       capsign sign [-n] -k private.pem [-m policy.ucl] [-o signed-image] image\n"
	    "       capsign verify [-c] [-p public.pem] image ...\n"
	    "       capsign show [-p public.pem] image\n"
	    "       capsign inspect [-p public.pem] image\n"
	    "       capsign resign [-n] -k new-private.pem [-p old-public.pem] [-o new-image] image\n"
	    "       capsign resign -r [-n] -k new-private.pem [-p old-public.pem] [-o new-tree] tree\n"
	    "       capsign remove [-r] -o new-output image-or-tree\n"
	    "       capsign seal -k private.pem -d domain -o signature artifact\n"
	    "       capsign check [-p public.pem] -d domain -s signature artifact\n"
	    "       capsign bundle-sign -k private.pem bundle.cap\n"
	    "       capsign bundle-verify [-p public.pem] bundle.cap\n"
	    "       capsign sign -r [-n] -k private.pem [-o new-tree] bundle-or-tree\n"
	    "       capsign verify -r [-p public.pem] bundle-or-tree\n");
	exit(64);
}
static void
copy_file(int input, int output, const struct stat *original)
{
	unsigned char buffer[16384];
	struct stat current;
	for (off_t pos = 0; pos < original->st_size;) {
		size_t take = original->st_size - pos < (off_t)sizeof(buffer) ?
		    (size_t)(original->st_size - pos) : sizeof(buffer);
		ssize_t n = pread(input, buffer, take, pos);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) errx(1, "short source read");
		for (ssize_t off = 0; off < n;) {
			ssize_t written = pwrite(output, buffer + off, (size_t)(n - off), pos + off);
			if (written < 0 && errno == EINTR) continue;
			if (written <= 0) err(1, "write output");
			off += written;
		}
		pos += n;
	}
	if (fstat(input, &current) < 0) err(1, "stat copied source");
	if (current.st_size != original->st_size ||
	    current.st_mtim.tv_sec != original->st_mtim.tv_sec ||
	    current.st_mtim.tv_nsec != original->st_mtim.tv_nsec ||
	    current.st_ctim.tv_sec != original->st_ctim.tv_sec ||
	    current.st_ctim.tv_nsec != original->st_ctim.tv_nsec)
		errx(1, "source changed while copying; use a quiescent input");
}
static void
validate_policy(const char *path)
{
	struct stat before, after;
	char error[256];
	unsigned char *data;
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &before) < 0) err(1, "%s", path);
	if (!S_ISREG(before.st_mode) || before.st_size <= 0 ||
	    (uint64_t)before.st_size > CAPIMAGE_POLICY_MAX)
		errx(1, "policy must be a bounded nonempty regular file");
	size_t size = (size_t)before.st_size;
	data = malloc(size);
	if (data == NULL) err(1, "policy allocation");
	for (size_t pos = 0; pos < size;) {
		ssize_t got = pread(fd, data + pos, size - pos, (off_t)pos);
		if (got < 0 && errno == EINTR) continue;
		if (got <= 0) errx(1, "policy changed or could not be read");
		pos += (size_t)got;
	}
	if (fstat(fd, &after) < 0 || before.st_size != after.st_size ||
	    before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
	    before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
	    before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
	    before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
		errx(1, "policy changed while reading; use a quiescent input");
	close(fd);
	if (capbundle_validate_unit_policy(data, size, error, sizeof(error)) < 0)
		errx(1, "%s: %s", path, error);
	free(data);
	printf("valid unit policy; bytes=%zu\n", size);
}
static int
verify_image(const char *path, const char *public, bool show, bool inspect)
{
	struct capimage_policy policy;
	char error[256];
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) { warn("%s", path); return (-1); }
	if (capimage_verify(fd, public, &policy, error, sizeof(error)) < 0) {
		warnx("%s: %s", path, error);
		close(fd);
		return (-1);
	}
	if (inspect) {
		struct capimage_elf_info image;
		if (capimage_cache_info(fd, &image, error, sizeof(error)) < 0) {
			warnx("%s: %s", path, error);
			capimage_policy_free(&policy);
			close(fd);
			return (-1);
		}
		printf("{\n  \"schema\": \"org.5bsd.capsign.image.v1\",\n"
		    "  \"container\": \"%s\",\n"
		    "  \"container_version\": %u,\n"
		    "  \"algorithm\": \"Ed25519\",\n"
		    "  \"digest_algorithm\": \"domain-separated-SHA256\",\n"
		    "  \"verification_key_selection\": \"%s\",\n"
		    "  \"policy_bytes\": %zu,\n  \"key_id\": \"",
		    "elf-note",
		    image.version,
		    public != NULL ? "explicit-key" : "system-catalogue", policy.size);
		for (size_t i = 0; i < sizeof(policy.key); i++) printf("%02x", policy.key[i]);
		printf("\",\n  \"signed_digest\": \"");
		for (size_t i = 0; i < sizeof(policy.digest); i++) printf("%02x", policy.digest[i]);
		printf("\"\n}\n");
	} else if (show) {
		if (fwrite(policy.data, 1, policy.size, stdout) != policy.size)
			err(1, "stdout");
	} else {
		printf("verified %s; key=", path);
		for (size_t i = 0; i < sizeof(policy.key); i++) printf("%02x", policy.key[i]);
		printf("; policy_bytes=%zu; digest=", policy.size);
		for (size_t i = 0; i < sizeof(policy.digest); i++) printf("%02x", policy.digest[i]);
		putchar('\n');
	}
	capimage_policy_free(&policy);
	close(fd);
	if (fflush(stdout) == EOF) err(1, "stdout");
	return (0);
}
int
main(int argc, char **argv)
{
	const char *command, *key = NULL, *public = NULL, *output = NULL;
	const char *manifest = NULL, *domain = NULL, *signature = NULL;
	struct stat st;
	char error[256];
	int ch, fd, out, sig, result;
	FILE *stream;
	bool recursive = false, keep_going = false, dry_run = false;
	bool seen[UCHAR_MAX + 1] = {false};
	const char *allowed = NULL;
	static const struct {
		const char *name, *plain, *recursive;
	} command_options[] = {
		{"key-id", "p", NULL}, {"note", "mo", NULL},
		{"validate-policy", "", NULL},
		{"sign", "nkmo", "rnko"}, {"verify", "pc", "rp"},
		{"show", "p", NULL}, {"inspect", "p", NULL},
		{"resign", "nkop", "rnkop"}, {"remove", "o", "ro"},
		{"seal", "kdo", NULL}, {"check", "pds", NULL},
		{"bundle-sign", "k", "rnko"}, {"bundle-verify", "p", "rp"}
	};
	static const struct option options[] = {
	    {"recursive", no_argument, NULL, 'r'},
	    {"dry-run", no_argument, NULL, 'n'},
	    {"continue", no_argument, NULL, 'c'},
	    {"manifest", required_argument, NULL, 'm'},
	    {"key", required_argument, NULL, 'k'},
	    {"public-key", required_argument, NULL, 'p'},
	    {"output", required_argument, NULL, 'o'},
	    {NULL, 0, NULL, 0}
	};
	if (argc < 2)
		usage();
	command = argv[1];
	argc--; argv++;
	while ((ch = getopt_long(argc, argv, "ncrk:p:o:m:d:s:", options, NULL)) != -1) {
		switch (ch) {
		case 'r': recursive = true; break;
		case 'c': keep_going = true; break;
		case 'n': dry_run = true; break;
		case 'k': key = optarg; break;
		case 'p': public = optarg; break;
		case 'o': output = optarg; break;
		case 'm': manifest = optarg; break;
		case 'd': domain = optarg; break;
		case 's': signature = optarg; break;
		default: usage();
		}
		seen[(unsigned char)ch] = true;
	}
	argc -= optind; argv += optind;
	for (size_t i = 0; i < sizeof(command_options) / sizeof(command_options[0]); i++) {
		if (strcmp(command, command_options[i].name) == 0) {
			allowed = recursive ? command_options[i].recursive : command_options[i].plain;
			break;
		}
	}
	if (allowed == NULL) usage();
	for (unsigned i = 0; i <= UCHAR_MAX; i++)
		if (seen[i] && strchr(allowed, i) == NULL) usage();
	if (recursive) {
		if (argc != 1 || manifest != NULL) usage();
		if (strcmp(command, "sign") == 0 || strcmp(command, "bundle-sign") == 0) {
			if (key == NULL || (output == NULL && !dry_run)) usage();
			if (dry_run) capsign_tree_preview(argv[0], output, key, NULL, false);
			else capsign_tree(argv[0], output, key, NULL);
		} else if (strcmp(command, "verify") == 0 || strcmp(command, "bundle-verify") == 0) {
			if (key != NULL || output != NULL) usage();
			capsign_tree(argv[0], NULL, NULL, public);
		} else if (strcmp(command, "resign") == 0) {
			if (key == NULL || (output == NULL && !dry_run) || domain != NULL || signature != NULL) usage();
			if (dry_run) capsign_tree_preview(argv[0], output, key, public, true);
			else capsign_tree_resign(argv[0], output, key, public);
		} else if (strcmp(command, "remove") == 0) {
			if (output == NULL || key != NULL || public != NULL || domain != NULL || signature != NULL) usage();
			capsign_tree_remove(argv[0], output);
		} else usage();
		return (0);
	}
	if (strcmp(command, "validate-policy") == 0) {
		if (argc != 1) usage();
		validate_policy(argv[0]);
		return (0);
	}
	if (strcmp(command, "key-id") == 0) {
		unsigned char raw[CAPIMAGE_KEY_SIZE];
		size_t length = sizeof(raw);
		if (argc != 0 || public == NULL) usage();
		fd = open(public, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0) err(1, "%s", public);
		stream = fdopen(fd, "r");
		if (stream == NULL) err(1, "fdopen");
		EVP_PKEY *pkey = PEM_read_PUBKEY(stream, NULL, NULL, NULL);
		fclose(stream);
		if (pkey == NULL || EVP_PKEY_base_id(pkey) != EVP_PKEY_ED25519 ||
		    EVP_PKEY_get_raw_public_key(pkey, raw, &length) != 1 || length != sizeof(raw))
			errx(1, "an Ed25519 public key is required");
		EVP_PKEY_free(pkey);
		for (size_t i = 0; i < length; i++) printf("%02x", raw[i]);
		putchar('\n');
		return (0);
	}
	if (strcmp(command, "note") == 0) {
		unsigned char *data;
		if (argc != 0 || manifest == NULL || output == NULL)
			usage();
		fd = open(manifest, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0 || fstat(fd, &st) < 0)
			err(1, "%s", manifest);
		if (!S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > CAPIMAGE_POLICY_MAX)
			errx(1, "manifest size/type invalid");
		data = malloc((size_t)st.st_size);
		if (data == NULL)
			err(1, "malloc");
		for (off_t off = 0; off < st.st_size;) {
			ssize_t n = read(fd, data + off, (size_t)(st.st_size - off));
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				errx(1, "short manifest read");
			off += n;
		}
		close(fd);
		stream = fopen(output, "wx");
		if (stream == NULL)
			err(1, "%s", output);
		result = capimage_note(stream, data, (size_t)st.st_size, error, sizeof(error));
		free(data);
		if (fclose(stream) != 0)
			err(1, "close output");
		if (result < 0)
			errx(1, "%s", error);
		return (0);
	}
	if (strcmp(command, "verify") == 0 || strcmp(command, "show") == 0 || strcmp(command, "inspect") == 0) {
		bool show = strcmp(command, "show") == 0;
		bool inspect = strcmp(command, "inspect") == 0;
		if (argc < 1 || ((show || inspect) && argc != 1) || key != NULL || output != NULL ||
		    manifest != NULL || domain != NULL || signature != NULL) usage();
		int failed = 0;
		for (int i = 0; i < argc; i++) {
			if (verify_image(argv[i], public, show, inspect) < 0) {
				failed = 1;
				if (!keep_going) break;
			}
		}
		return (failed);
	}
	if (argc != 1)
		usage();
	if (strcmp(command, "bundle-sign") == 0) {
		if (key == NULL) usage();
		if (capbundle_seal(argv[0], key, error, sizeof(error)) < 0)
			errx(1, "%s", error);
		return (0);
	}
	if (strcmp(command, "bundle-verify") == 0) {
		struct capbundle *bundle;
		if (capbundle_open_trusted(argv[0], public, true, &bundle, error, sizeof(error)) < 0)
			errx(1, "%s", error);
		if (capbundle_verify(bundle, error, sizeof(error)) < 0)
			errx(1, "%s", error);
		printf("verified bundle %s; units=%u\n", capbundle_id(bundle), capbundle_nservices(bundle));
		capbundle_close(bundle);
		return (0);
	}
	fd = open(argv[0], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		err(1, "%s", argv[0]);
	if (strcmp(command, "check") == 0) {
		if (signature == NULL || domain == NULL)
			usage();
		sig = open(signature, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (sig < 0)
			err(1, "%s", signature);
		if (capimage_check_seal(fd, sig, domain, public, error, sizeof(error)) < 0)
			errx(1, "%s", error);
		close(sig); close(fd);
		printf("verified %s\n", argv[0]);
		return (0);
	}
	bool removing = strcmp(command, "remove") == 0;
	bool resigning = strcmp(command, "resign") == 0;
	if (strcmp(command, "sign") != 0 && strcmp(command, "seal") != 0 && !removing && !resigning)
		usage();
	if ((!removing && key == NULL) || (output == NULL && !dry_run) ||
	    (removing && (key != NULL || public != NULL || manifest != NULL || domain != NULL || signature != NULL)) ||
	    (strcmp(command, "seal") == 0 && domain == NULL))
		usage();
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
	    (uint64_t)st.st_size > CAPIMAGE_FILE_MAX)
		errx(1, "invalid input size/type");
	if (asprintf(&temporary, "%s.tmp.XXXXXX", output != NULL ? output : "/tmp/capsign-dryrun") < 0)
		err(1, "asprintf");
	out = mkstemp(temporary);
	if (out < 0)
		err(1, "%s", temporary);
	if (atexit(cleanup_temporary) != 0) { unlink(temporary); errx(1, "register temporary cleanup"); }
	if (removing) {
		copy_file(fd, out, &st);
		result = capimage_remove(out, error, sizeof(error));
	} else if (strcmp(command, "sign") == 0 || resigning) {
		copy_file(fd, out, &st);
		if (resigning) {
			struct capimage_policy policy;

			/* Authenticate the private copy we will re-sign. Reading policy
			 * from the source and later copying it would leave a race. */
			if (capimage_verify(out, public, &policy, error, sizeof(error)) < 0)
				errx(1, "%s", error);
			capimage_policy_free(&policy);
		}
		if (manifest != NULL) {
			struct stat mst;
			int mfd = open(manifest, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			if (mfd < 0 || fstat(mfd, &mst) < 0 || !S_ISREG(mst.st_mode) ||
			    mst.st_size <= 0 || mst.st_size > CAPIMAGE_POLICY_MAX) {
				unlink(temporary); errx(1, "invalid manifest size/type");
			}
			unsigned char *data = malloc((size_t)mst.st_size);
			if (data == NULL) { unlink(temporary); err(1, "manifest allocation"); }
			off_t pos = 0;
			while (pos < mst.st_size) {
				ssize_t n = read(mfd, data + pos, (size_t)(mst.st_size - pos));
				if (n < 0 && errno == EINTR) continue;
				if (n <= 0) { unlink(temporary); errx(1, "short manifest read"); }
				pos += n;
			}
			close(mfd);
			result = capimage_embed(out, data, (size_t)mst.st_size, error, sizeof(error));
			free(data);
			if (result < 0) { unlink(temporary); errx(1, "%s", error); }
		}
		result = capimage_sign(out, key, error, sizeof(error));
	} else
		result = capimage_seal(fd, out, domain, key, error, sizeof(error));
	if (result < 0) {
		unlink(temporary);
		errx(1, "%s", error);
	}
	if (dry_run) {
		/* Exercise the real copy, embedding and signing path, but never link
		 * a result into place. This does not promise a later publish succeeds. */
		if (close(out) < 0) err(1, "close dry-run image");
		close(fd);
		cleanup_temporary();
		free(temporary);
		temporary = NULL;
		puts("validated image signing; no output published");
		return (0);
	}
	/* Publish complete output without overwriting any existing object. */
	if (fchmod(out, (removing || resigning || strcmp(command, "sign") == 0) ? (st.st_mode & 0777) : 0444) < 0 ||
	    fsync(out) < 0 || close(out) < 0 || link(temporary, output) < 0) {
		int saved = errno;
		unlink(temporary);
		errno = saved;
		err(1, "publish %s", output);
	}
	unlink(temporary);
	free(temporary);
	temporary = NULL;
	close(fd);
	return (0);
}
