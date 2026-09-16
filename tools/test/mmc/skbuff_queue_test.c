/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
struct sk_buff { struct sk_buff *next, *prev; unsigned refcnt; };
struct sk_buff_head_l { struct sk_buff *next, *prev; };
struct sk_buff_head { struct sk_buff *next, *prev; unsigned qlen; };
#define SKB_TRACE(...) ((void)0)
#define SKB_TRACE2(...) ((void)0)
#define SKB_TRACE_FMT(...) ((void)0)
#define WRITE_ONCE(p,v) ((p)=(v))
#define refcount_read(p) (*(p))
#include "power_functions.h"
int main(void) {
 struct sk_buff_head q;
 struct sk_buff packets[16]={0};
 for (unsigned length=0;length<=16;length++) {
  __skb_queue_head_init(&q);
  assert(skb_peek(&q)==NULL && __skb_peek(&q)==(struct sk_buff *)&q);
  for (unsigned i=0;i<length;i++) __skb_queue_tail(&q,&packets[i]);
  assert(q.qlen==length);
  struct sk_buff *p=skb_peek(&q);
  for (unsigned i=0;i<length;i++) {
   assert(p==&packets[i]);
   assert(skb_queue_is_last(&q,p)==(i==length-1));
   p=skb_peek_next(p,&q);
  }
  assert(p==NULL);
  for (unsigned i=0;i<length;i++) {
   assert(__skb_dequeue(&q)==&packets[i]);
   assert(packets[i].next==NULL && packets[i].prev==NULL);
   assert(q.qlen==length-i-1);
  }
  assert(__skb_dequeue(&q)==NULL && q.prev==(struct sk_buff *)&q);
 }
 for (unsigned refs=1;refs<=16;refs++) {
  packets[0].refcnt=refs;
  assert(skb_cloned(&packets[0])==(refs>1));
 }
 puts("PASS: SDIO queue sentinel, traversal/last packet, dequeue reset and shared allocation detection");
 return 0;
}
