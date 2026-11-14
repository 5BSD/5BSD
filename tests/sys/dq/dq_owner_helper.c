/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * dq_owner_test's exec'd image: it reports, by its exit status, how many
 * of the descriptors it was started with are the queue device.  A queue
 * descriptor never survives an exec (sc-q), so the answer is 0; 100 stands
 * for that many or more, 101 for a device that cannot be examined.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>

#define	DQ_DEVICE	"/dev/dq"

int
main(void)
{
	struct stat dev, sb;
	int fd, max, n;

	if (stat(DQ_DEVICE, &dev) != 0 || !S_ISCHR(dev.st_mode))
		return (101);
	max = getdtablesize();
	if (max > 4096)
		max = 4096;
	n = 0;
	for (fd = 0; fd < max; fd++) {
		if (fstat(fd, &sb) == 0 && S_ISCHR(sb.st_mode) &&
		    sb.st_rdev == dev.st_rdev)
			n++;
	}
	return (n > 100 ? 100 : n);
}
