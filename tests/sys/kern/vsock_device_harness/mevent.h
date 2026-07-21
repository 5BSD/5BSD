/* Mock of bhyve mevent.h for the vsock device harness. */
#ifndef MOCK_MEVENT_H
#define MOCK_MEVENT_H
enum ev_type { EVF_READ, EVF_WRITE, EVF_TIMER, EVF_VNODE, EVF_SIGNAL };
struct mevent;
struct mevent *mevent_add(int, enum ev_type,
    void (*)(int, enum ev_type, void *), void *);
struct mevent *mevent_add_disabled(int, enum ev_type,
    void (*)(int, enum ev_type, void *), void *);
int mevent_enable(struct mevent *);
int mevent_disable(struct mevent *);
int mevent_delete(struct mevent *);
int mevent_delete_close(struct mevent *);
#endif
