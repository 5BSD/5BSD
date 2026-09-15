/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef int gfp_t;
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#define ETH_ALEN 6
#define ETH_HLEN 14
#define IFNAMSIZ 16
#define BRCMF_E_IF 54
#define BRCMF_DCMD_MAXLEN 8192
#define ETH_P_LINK_CTL 0x886c
#define BRCM_OUI "\x00\x10\x18"
#define BCMILCP_BCM_SUBTYPE_EVENT 1
#define cpu_to_be16(v) htons(v)
#define unlikely(v) (v)
struct ethhdr { u8 h_dest[6],h_source[6];__be16 h_proto; } __packed;
#include "event_wire.h"
struct brcmf_fweh_info { u32 num_event_codes; bool evt_handler[128]; };
struct brcmf_pub { struct brcmf_fweh_info *fweh; };
struct brcmf_fweh_queue_item { u32 code,datalen;u8 ifidx,ifaddr[6];struct brcmf_event_msg_be emsg;u8 data[]; };
struct sk_buff { u8 *head,*data,*mac;u32 len,data_len;u16 protocol; };
static unsigned queued,allocs;
static bool fail_alloc;
static u8 payload[5]={1,2,3,4,5};
static void *alloc_event(size_t size,int flags) { (void)flags;if(fail_alloc)return NULL;allocs++;return calloc(1,size); }
#define kzalloc_flex(v,member,count,gfp) alloc_event(sizeof(v)+(count),gfp)
static u32 get_unaligned_be32(const void *p) { u32 value;memcpy(&value,p,4);return ntohl(value); }
static u16 get_unaligned_be16(const void *p) { u16 value;memcpy(&value,p,2);return ntohs(value); }
static inline size_t skb_headroom(struct sk_buff *s) { return s->data-s->head; }
static inline u32 skb_headlen(struct sk_buff *s) { return s->len-s->data_len; }
static u8 *skb_mac_header(struct sk_buff *s) { return s->mac; }
static void brcmf_fweh_queue_event(struct brcmf_fweh_info *f,struct brcmf_fweh_queue_item *e) {
 assert(f && allocs==1 && e->datalen==sizeof(payload));
 assert(!memcmp(e->data,payload,sizeof(payload)));queued++;allocs--;free(e);
}
#include "power_functions.h"
int main(void) {
 size_t page=sysconf(_SC_PAGESIZE);
 u8 *mapping=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(mapping!=MAP_FAILED && mprotect(mapping+page,page,PROT_NONE)==0);
 struct brcmf_fweh_info f={.num_event_codes=128};f.evt_handler[1]=true;
 struct brcmf_pub d={.fweh=&f};
 struct brcmf_event valid={0};valid.hdr.subtype=htons(32769);
 memcpy(valid.hdr.oui,BRCM_OUI,3);valid.hdr.usr_subtype=htons(BCMILCP_BCM_SUBTYPE_EVENT);
 valid.msg.event_type=htonl(BRCMF_E_IF);valid.msg.datalen=htonl(sizeof(payload));
 /* Every truncated fixed header lies immediately against an inaccessible page. */
 for(unsigned n=0;n<sizeof(valid);n++) {
  u8 *p=mapping+page-n;memcpy(p,&valid,n);
  brcmf_fweh_process_event(&d,(void *)p,n,0);assert(!queued && !allocs);
 }
 u8 *p=mapping+page-sizeof(valid)-sizeof(payload);
 struct brcmf_event *event=(void *)p;memcpy(event,&valid,sizeof(valid));memcpy(event+1,payload,sizeof(payload));
 /* Every short IF payload must be rejected even if its declared length fits. */
 for(unsigned n=0;n<sizeof(payload);n++) {
  event->msg.datalen=htonl(n);
  brcmf_fweh_process_event(&d,event,sizeof(valid)+n,0);assert(!queued && !allocs);
 }
 event->msg.datalen=htonl(sizeof(payload));
 struct sk_buff skb={.head=p,.mac=p,.data=p+ETH_HLEN,.len=sizeof(valid)+sizeof(payload)-ETH_HLEN,.protocol=htons(ETH_P_LINK_CTL)};
 assert(skb_headroom(&skb)==ETH_HLEN && skb_headlen(&skb)==skb.len);
 brcmf_fweh_process_skb(&d,&skb,32769,0);assert(queued==1);
 brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==2);
 /* Fragmented fixed header: total bytes cannot authorize reading the header. */
 u8 *short_head=mapping+page-ETH_HLEN;
 memcpy(short_head,&valid,ETH_HLEN);
 struct sk_buff fragment={.head=short_head,.mac=short_head,.data=mapping+page,.len=200,.data_len=200,.protocol=htons(ETH_P_LINK_CTL)};
 brcmf_fweh_process_skb(&d,&fragment,0,0);assert(queued==2);
 /* Restore the packet overwritten by the boundary test. */
 memcpy(event,&valid,sizeof(valid));memcpy(event+1,payload,sizeof(payload));
 skb.data_len=sizeof(payload);brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==2);skb.data_len=0;
 skb.mac++;brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==2);skb.mac--;
 skb.head=skb.data;brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==2);skb.head=p;
 fail_alloc=true;brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==2 && !allocs);fail_alloc=false;
 event->msg.datalen=htonl(UINT32_MAX);brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==2);
 event->msg.datalen=htonl(sizeof(payload));event->msg.event_type=htonl(128);
 brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==2);
 event->msg.event_type=htonl(1);brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==3);
 d.fweh=NULL;brcmf_fweh_process_skb(&d,&skb,0,0);assert(queued==3);
 assert(munmap(mapping,2*page)==0);
 puts("PASS: guard-page event headers, short IF payloads, fragment bounds, event indices and allocation failure");
 return 0;
}
