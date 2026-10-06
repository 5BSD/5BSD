#include <sys/types.h>
#include <sys/capsicum.h>
#include <tracecmp.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv)
{
 int fd = -1;
 cap_rights_t rights;
 closefrom(3);
 if (argc != 2) return 64;
 int rc = tracecmp_open(&fd);
 if (!strcmp(argv[1], "deny")) {
  if (rc == 0 || fd >= 0 || errno != EOPNOTSUPP)
   errx(1, "unexpected consumer result rc=%d fd=%d errno=%d", rc, fd, errno);
  puts("BSDTRACE_CONSUMER_DENY_PASS");return 0;
 }
 if (rc < 0) err(1, "BSDTrace consumer open");
 if (cap_rights_get(fd, &rights) < 0) err(1, "consumer rights");
 if (!cap_rights_is_set(&rights, CAP_READ, CAP_WRITE, CAP_FSTAT, CAP_IOCTL) ||
     cap_rights_is_set(&rights, CAP_SEEK) || cap_rights_is_set(&rights, CAP_LOOKUP))
  errx(1, "unexpected consumer rights");
 close(fd);
 puts("BSDTRACE_CONSUMER_OPEN_PASS");return 0;
}
