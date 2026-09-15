/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
typedef unsigned long ulong;
struct list_head { struct list_head *next,*prev; };
static void list_add_tail(struct list_head *n,struct list_head *h) { n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n; }
static bool list_empty(struct list_head *h) { return h->next==h; }
static void list_del(struct list_head *n) { n->next->prev=n->prev;n->prev->next=n->next; }
#define list_first_entry(h,t,m) ((t *)((char *)((h)->next)-offsetof(t,m)))
struct work_struct { void *func; bool pending; };
struct brcmf_fweh_queue_item { struct list_head q; };
struct brcmf_fweh_info { bool stopping; pthread_mutex_t evt_q_lock;struct list_head event_q;struct work_struct event_work;void *event_mask; };
struct brcmf_pub { struct brcmf_fweh_info *fweh; };
#define spin_lock_irqsave(m,f) do { (f)=0;assert(pthread_mutex_lock(m)==0); } while(0)
#define spin_unlock_irqrestore(m,f) do { (void)(f);assert(pthread_mutex_unlock(m)==0); } while(0)
static struct brcmf_fweh_info *active_fweh;
static unsigned freed_events,scheduled;
static bool worker_active,release_worker,drain_entered,quiesced,callback_read;
static pthread_mutex_t worker_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t worker_cv=PTHREAD_COND_INITIALIZER;
static void schedule_work(struct work_struct *w) {
 /* The stop flag and schedule operation must share the queue lock. */
 int locked=pthread_mutex_trylock(&active_fweh->evt_q_lock);
 assert(locked==EBUSY || locked==EDEADLK);
 w->pending=true;scheduled++;
}
static void cancel_work_sync(struct work_struct *w) {
 pthread_mutex_lock(&worker_lock);drain_entered=true;
 pthread_cond_broadcast(&worker_cv);
 while(worker_active) pthread_cond_wait(&worker_cv,&worker_lock);
 w->pending=false;pthread_mutex_unlock(&worker_lock);
}
static void kfree(void *p) { if(p) { assert(p!=active_fweh);freed_events++;free(p); } }
#include "power_functions.h"
static void *quiesce_thread(void *p) {
 brcmf_fweh_quiesce(p);pthread_mutex_lock(&worker_lock);quiesced=true;
 pthread_cond_broadcast(&worker_cv);pthread_mutex_unlock(&worker_lock);return NULL;
}
static void *callback_thread(void *p) {
 (void)p;pthread_mutex_lock(&worker_lock);
 while(!release_worker) pthread_cond_wait(&worker_cv,&worker_lock);
 assert(!quiesced);callback_read=true;worker_active=false;
 pthread_cond_broadcast(&worker_cv);pthread_mutex_unlock(&worker_lock);return NULL;
}
static struct brcmf_fweh_queue_item *event(void) { return calloc(1,sizeof(struct brcmf_fweh_queue_item)); }
int main(void) {
 struct brcmf_fweh_info f={.evt_q_lock=PTHREAD_MUTEX_INITIALIZER,.event_work={.func=(void *)1}};
 struct brcmf_pub pub={.fweh=&f};active_fweh=&f;f.event_q.next=f.event_q.prev=&f.event_q;
 brcmf_fweh_queue_event(&f,event());brcmf_fweh_queue_event(&f,event());
 assert(scheduled==2 && freed_events==0);
 worker_active=true;pthread_t callback,stopper;
 pthread_create(&callback,NULL,callback_thread,NULL);pthread_create(&stopper,NULL,quiesce_thread,&pub);
 pthread_mutex_lock(&worker_lock);
 while(!drain_entered) pthread_cond_wait(&worker_cv,&worker_lock);
 assert(!quiesced && !callback_read);
 pthread_mutex_unlock(&worker_lock);
 /* A racing producer after stop neither queues nor schedules its event. */
 brcmf_fweh_queue_event(&f,event());assert(scheduled==2 && freed_events==1);
 pthread_mutex_lock(&worker_lock);release_worker=true;pthread_cond_broadcast(&worker_cv);pthread_mutex_unlock(&worker_lock);
 pthread_join(callback,NULL);pthread_join(stopper,NULL);
 assert(quiesced && callback_read && freed_events==3 && list_empty(&f.event_q));
 brcmf_fweh_quiesce(&pub);assert(freed_events==3);
 brcmf_fweh_queue_event(&f,event());assert(freed_events==4 && scheduled==2);
 pthread_mutex_destroy(&f.evt_q_lock);
 puts("PASS: firmware event shutdown excludes producers, joins active callbacks and frees canceled events");
 return 0;
}
