/* SPDX-License-Identifier: BSD-2-Clause */
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond=PTHREAD_COND_INITIALIZER;
static int ready;
static void cleanup(void *p) { assert(pthread_mutex_unlock(p)==0); }
static void *worker(void *p) {
 (void)p; assert(pthread_mutex_lock(&mutex)==0);
 pthread_cleanup_push(cleanup,&mutex);
 ready=1; pthread_cond_signal(&cond);
 for (;;) pthread_cond_wait(&cond,&mutex);
 pthread_cleanup_pop(1); return NULL;
}
int main(void) {
 pthread_t t; void *result;
 assert(pthread_mutex_lock(&mutex)==0);
 assert(pthread_create(&t,NULL,worker,NULL)==0);
 usleep(20000); /* Force the child through the contended mutex path. */
 while (!ready) assert(pthread_cond_wait(&cond,&mutex)==0);
 assert(pthread_cancel(t)==0); assert(pthread_mutex_unlock(&mutex)==0);
 assert(pthread_join(t,&result)==0); assert(result==PTHREAD_CANCELED);
 assert(pthread_cond_destroy(&cond)==0); assert(pthread_mutex_destroy(&mutex)==0);
 return 0;
}
