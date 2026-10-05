/* SPDX-License-Identifier: BSD-2-Clause */
/* Regression: epoll temporary masks must not resurrect sigsuspend masks. */
#include "linux_test.h"

struct sigaction_ {
 void (*handler)(int);
 unsigned long flags;
 void (*restorer)(void);
 unsigned long mask;
};
struct event_ { unsigned int events; unsigned long data; } __attribute__((packed));
static volatile int hits;
static void handler(int sig) { if (sig == 10) hits++; }
void restorer(void);
__asm__(".globl restorer\nrestorer:\n mov $15,%eax\n syscall\n hlt\n");
static unsigned long pwr = 1UL << 29, usr = 1UL << 9;
static int failures, checks;
static void check(int ok, const char *name) {
 checks++;
 if (!ok) { failures++; msg(name); msg(" FAIL\n"); }
}
static unsigned long getmask(void) {
 unsigned long mask = ~0UL;
 check(sys4(SYS_rt_sigprocmask, 2, 0, &mask, 8) == 0, "getmask");
 return mask;
}
static void setmask(unsigned long mask) {
 check(sys4(SYS_rt_sigprocmask, 2, &mask, 0, 8) == 0, "setmask");
}
static long wait_(int version, int fd, void *event, int n, int ms,
    unsigned long *mask) {
 struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
 if (version == 1)
  return sys6(281, fd, event, n, ms, mask, 8);
 return sys6(441, fd, event, n, &ts, mask, 8);
}
static int test(int argc, char **argv, char **envp) {
 (void)argc; (void)argv; (void)envp;
 struct sigaction_ sa = { handler, 0x04000000, restorer, 0 };
 struct event_ event = { 1, 42 }, out;
 unsigned long empty = 0;
 long pid = sys0(SYS_getpid), fd = sys1(291, 0), efd;
 check(fd >= 0, "epoll_create");
 check(sys4(SYS_rt_sigaction, 10, &sa, 0, 8) == 0, "sigaction");
 if (failures) return 1;
 for (int v = 1; v <= 2; v++) {
  for (int round = 0; round < 10; round++) {
   /* Seed td_oldsigmask with SIGPWR blocked, as a suspend handler can. */
   setmask(pwr | usr);
   int beforehits = hits;
   check(sys2(SYS_kill, pid, 10) == 0, "queue signal");
   check(sys2(130, &pwr, 8) == -EINTR, "sigsuspend");
   check(hits == beforehits + 1, "sigsuspend handler");
   setmask(empty);
   check(wait_(v, fd, &out, 1, 0, &empty) == 0, "zero timeout");
   check(getmask() == empty, "stale SIGPWR mask restored");
   /* Also preserve a nonempty original mask and NULL-mask behavior. */
   setmask(usr);
   check(wait_(v, fd, &out, 1, 1, &empty) == 0, "finite timeout");
   check(getmask() == usr, "timeout mask");
   check(wait_(v, fd, &out, 1, 0, 0) == 0, "NULL mask timeout");
   check(getmask() == usr, "NULL mask preserved");
   check(wait_(v, -1, &out, 1, 0, &empty) == -9, "EBADF");
   check(getmask() == usr, "EBADF mask");
   check(wait_(v, fd, &out, 0, 0, &empty) == -22, "EINVAL");
   check(getmask() == usr, "EINVAL mask");
   check(wait_(v, fd, &out, 1, 0, (void *)1) == -14, "mask EFAULT");
   check(getmask() == usr, "mask EFAULT preserved");
   /* Both handler restart policies must return EINTR, preserving mask. */
   for (int restart = 0; restart < 2; restart++) {
    sa.flags = 0x04000000 | (restart ? 0x10000000 : 0);
    check(sys4(SYS_rt_sigaction, 10, &sa, 0, 8) == 0, "sigaction restart");
    beforehits = hits;
    check(sys2(SYS_kill, pid, 10) == 0, "queue interrupt");
    check(wait_(v, fd, &out, 1, 100, &empty) == -EINTR, "interrupted wait");
    check(hits == beforehits + 1, "interrupt handler");
    check(getmask() == usr, "interrupted mask");
   }
   efd = sys2(290, 1, 0);
   check(efd >= 0, "eventfd");
   check(sys4(233, fd, 1, efd, &event) == 0, "epoll add");
   check(wait_(v, fd, (void *)1, 1, 0, &empty) == -14, "event copyout EFAULT");
   check(getmask() == usr, "copyout error mask");
   check(wait_(v, fd, &out, 1, 0, &empty) == 1, "ready event");
   check(out.data == 42 && (out.events & 1), "event data");
   check(getmask() == usr, "ready event mask");
   sys1(SYS_close, efd);
   setmask(empty);
  }
 }
 sys1(SYS_close, fd);
 msgnum("EPOLL_SIGNAL_CHECKS ", checks);
 msgnum("EPOLL_SIGNAL_FAILURES ", failures);
 return failures ? 1 : 0;
}
