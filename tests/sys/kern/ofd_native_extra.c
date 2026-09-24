/* SPDX-License-Identifier: BSD-2-Clause */
/* Native-only rights, introspection, and libc cancellation contracts. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#ifndef F_OFD_GETLK
#define F_OFD_GETLK 25
#define F_OFD_SETLK 26
#define F_OFD_SETLKW 27
#endif
#ifndef KLOCKF_TYPE_OFD
#define KLOCKF_TYPE_OFD 4
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d errno %d\n",__LINE__,errno); return 1; } } while (0)
static atomic_int ready, cleaned;
static int waiterfd;
static void cleanup(void *unused)
{
	(void)unused;
	close(waiterfd);
	atomic_store(&cleaned,1);
}
static void *waiter(void *unused)
{
	(void)unused;
	struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
	pthread_cleanup_push(cleanup,NULL);
	atomic_store(&ready,1);
	/* The main thread's conflicting lock is retained until cancellation. */
	int r = fcntl(waiterfd,F_OFD_SETLKW,&fl);
	(void)r;
	pthread_cleanup_pop(1);
	return NULL;
}
int main(void)
{
	int a = open("file",O_CREAT|O_RDWR|O_TRUNC,0600);
	struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
	CHECK(a >= 0);
	int before = fcntl(a,F_GETFL);
	CHECK(before >= 0 && fcntl(a,F_OFD_SETLK,&fl) == 0);
	CHECK(fcntl(a,F_GETFL) == before); /* Internal tracking is not an open flag. */
	int restricted = dup(a); CHECK(restricted >= 0);
	cap_rights_t rights;
	cap_rights_init(&rights,CAP_FSTAT);
	CHECK(cap_rights_limit(restricted,&rights) == 0);
	int commands[] = {F_OFD_GETLK,F_OFD_SETLK,F_OFD_SETLKW};
	for (unsigned i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
		errno = 0;
		CHECK(fcntl(restricted,commands[i],&fl) == -1 && errno == ENOTCAPABLE);
	}
	CHECK(close(restricted) == 0);

	size_t len = 0;
	CHECK(sysctlbyname("kern.lockf",NULL,&len,NULL,0) == 0 && len > 0);
	void *data = malloc(len); CHECK(data != NULL);
	CHECK(sysctlbyname("kern.lockf",data,&len,NULL,0) == 0);
	int found = 0;
	for (size_t off = 0; off < len;) {
		struct kinfo_lockf *kl = (struct kinfo_lockf *)((char *)data+off);
		CHECK(len-off >= sizeof(*kl) && kl->kl_structsize >= (int)sizeof(*kl) &&
		    (size_t)kl->kl_structsize <= len-off);
		if (kl->kl_type == KLOCKF_TYPE_OFD && kl->kl_pid == -1)
			found++;
		off += kl->kl_structsize;
	}
	free(data); CHECK(found > 0);

	for (int i = 0; i < 16; i++) {
		pthread_t thread; void *value;
		waiterfd = open("file",O_RDWR); CHECK(waiterfd >= 0);
		atomic_store(&ready,0); atomic_store(&cleaned,0);
		CHECK(pthread_create(&thread,NULL,waiter,NULL) == 0);
		while (!atomic_load(&ready)) {
			struct timespec ts = {0,1000000}; nanosleep(&ts,NULL);
		}
		struct timespec ts = {0,20000000}; nanosleep(&ts,NULL);
		CHECK(pthread_cancel(thread) == 0);
		CHECK(pthread_join(thread,&value) == 0 && value == PTHREAD_CANCELED);
		CHECK(atomic_load(&cleaned));
	}
	CHECK(close(a) == 0);
	a = open("file",O_RDWR); CHECK(a >= 0);
	CHECK(fcntl(a,F_OFD_SETLK,&fl) == 0 && close(a) == 0);
	return 0;
}
