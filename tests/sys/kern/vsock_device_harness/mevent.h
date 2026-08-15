/* Mock of bhyve mevent.h for the vsock device harness. */
#ifndef MOCK_MEVENT_H
#define MOCK_MEVENT_H
enum ev_type { EVF_READ, EVF_WRITE, EVF_TIMER, EVF_VNODE, EVF_SIGNAL };
#define	EVFF_ATTRIB	0x0001
struct mevent;
typedef void (*mevent_param_cleanup_t)(void *);
struct mevent *mevent_add(int, enum ev_type,
    void (*)(int, enum ev_type, void *), void *);
struct mevent *mevent_add_flags(int, enum ev_type, int,
    void (*)(int, enum ev_type, void *), void *);
struct mevent *mevent_add_disabled(int, enum ev_type,
    void (*)(int, enum ev_type, void *), void *);
struct mevent *mevent_add_cleanup(int, enum ev_type,
    void (*)(int, enum ev_type, void *), void *, mevent_param_cleanup_t);
int mevent_enable(struct mevent *);
int mevent_disable(struct mevent *);
int mevent_delete(struct mevent *);
int mevent_delete_sync(struct mevent *);
int mevent_delete_close_sync(struct mevent *);
int mevent_delete_close(struct mevent *);
int mevent_timer_update(struct mevent *, int);
void mevent_dispatch(void);
#endif
