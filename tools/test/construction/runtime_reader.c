/* SPDX-License-Identifier: BSD-2-Clause */
/* Read actual DB records directly, with no flat-file or NSS fallback. */
#include <sys/types.h>
#include <arpa/inet.h>
#include <db.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
account(const char *root, const char *database, const char *name,
    uint32_t uid, const char *password)
{
	DB *db;
	DBT key, data, byuid;
	char path[1024], keybuf[256];
	uint32_t number;
	size_t length;
	unsigned char *saved;

	if (snprintf(path, sizeof(path), "%s/etc/%s", root, database) >= (int)sizeof(path))
		errx(1, "database path");
	db = dbopen(path, O_RDONLY, 0, DB_HASH, NULL);
	if (db == NULL)
		err(1, "open %s", database);
	keybuf[0] = _PW_VERSIONED(_PW_KEYBYNAME, _PWD_CURRENT_VERSION);
	if (strlen(name) >= sizeof(keybuf) - 1)
		errx(1, "name length");
	memcpy(keybuf + 1, name, strlen(name));
	key.data = keybuf;
	key.size = strlen(name) + 1;
	if (db->get(db, &key, &data, 0) != 0)
		errx(1, "missing name in %s", database);
	length = strlen(name) + 1 + strlen(password) + 1;
	if (data.size < length + sizeof(number) ||
	    memcmp(data.data, name, strlen(name) + 1) != 0 ||
	    memcmp((char *)data.data + strlen(name) + 1, password, strlen(password) + 1) != 0)
		errx(1, "wrong account strings in %s", database);
	memcpy(&number, (char *)data.data + length, sizeof(number));
	if (ntohl(number) != uid)
		errx(1, "wrong UID in %s", database);
	length = data.size;
	saved = malloc(length);
	if (saved == NULL)
		err(1, "malloc");
	memcpy(saved, data.data, length);
	keybuf[0] = _PW_VERSIONED(_PW_KEYBYUID, _PWD_CURRENT_VERSION);
	number = htonl(uid);
	memcpy(keybuf + 1, &number, sizeof(number));
	key.size = sizeof(number) + 1;
	if (db->get(db, &key, &byuid, 0) != 0 || byuid.size != length ||
	    memcmp(byuid.data, saved, length) != 0)
		errx(1, "UID index disagrees in %s", database);
	free(saved);
	if (db->close(db) != 0)
		err(1, "close database");
}

static void
service(const char *root, unsigned port)
{
	DB *db;
	DBT key, indirect, data;
	char path[1024], keybuf[256], expected[256];

	if (snprintf(path, sizeof(path), "%s/var/db/services.db", root) >= (int)sizeof(path))
		errx(1, "services path");
	db = dbopen(path, O_RDONLY, 0, DB_HASH, NULL);
	if (db == NULL)
		err(1, "open services database");
	snprintf(expected, sizeof(expected), "fixture %u/tcp alias ", port);
	for (unsigned i = 0; i < 3; i++) {
		if (i == 0)
			snprintf(keybuf, sizeof(keybuf), "\376fixture/tcp");
		else if (i == 1)
			snprintf(keybuf, sizeof(keybuf), "\376alias/tcp");
		else
			snprintf(keybuf, sizeof(keybuf), "\377%u/tcp", port);
		key.data = keybuf;
		key.size = strlen(keybuf) + 1;
		if (db->get(db, &key, &indirect, 0) != 0 ||
		    db->get(db, &indirect, &data, 0) != 0 ||
		    data.size != strlen(expected) + 1 || strcmp(data.data, expected) != 0)
			errx(1, "services name/alias/port index differs");
	}
	if (db->close(db) != 0)
		err(1, "close services database");
}

int
main(int argc, char **argv)
{
	char path[1024];
	unsigned long uid, port;
	int fd;

	if (argc != 4)
		errx(1, "root UID port required");
	uid = strtoul(argv[2], NULL, 10);
	port = strtoul(argv[3], NULL, 10);
	if (uid > UINT32_MAX || port > 65535)
		errx(1, "test identity range");
	account(argv[1], "pwd.db", "fixture", uid, "*");
	service(argv[1], port);
	if (geteuid() == 0)
		account(argv[1], "spwd.db", "fixture", uid, "fixture-secret");
	else {
		if (snprintf(path, sizeof(path), "%s/etc/spwd.db", argv[1]) >= (int)sizeof(path))
			errx(1, "secure database path");
		fd = open(path, O_RDONLY);
		if (fd != -1 || errno != EACCES)
			errx(1, "secure database was not denied");
	}
	return (0);
}
