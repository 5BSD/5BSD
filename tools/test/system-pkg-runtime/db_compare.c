/* SPDX-License-Identifier: BSD-2-Clause */
/* Compare logical db(3) records without modifying either database. */
#include <sys/types.h>
#include <db.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

static size_t
compare(DB *left, DB *right)
{
	DBT key, value, other;
	size_t count;
	int status;

	count = 0;
	for (status = left->seq(left, &key, &value, R_FIRST); status == 0;
	    status = left->seq(left, &key, &value, R_NEXT)) {
		if (right->get(right, &key, &other, 0) != 0 ||
		    value.size != other.size ||
		    memcmp(value.data, other.data, value.size) != 0)
			errx(1, "database records differ");
		count++;
	}
	if (status != 1)
		errx(1, "database traversal failed");
	return (count);
}

int
main(int argc, char **argv)
{
	DB *left, *right;
	size_t count;

	if (argc != 3)
		errx(1, "usage: db_compare left right");
	if ((left = dbopen(argv[1], O_RDONLY, 0, DB_HASH, NULL)) == NULL)
		err(1, "%s", argv[1]);
	if ((right = dbopen(argv[2], O_RDONLY, 0, DB_HASH, NULL)) == NULL)
		err(1, "%s", argv[2]);
	count = compare(left, right);
	if (compare(right, left) != count)
		errx(1, "database counts differ");
	if (left->close(left) != 0 || right->close(right) != 0)
		err(1, "database close");
	printf("DB_RECORDS_EQUAL %zu\n", count);
	return (0);
}
