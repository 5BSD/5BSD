#include "kmock.h"
struct vnet _thevnet = { 0 };
struct vnet *curvnet = &_thevnet;
volatile int ticks = 0;
uint32_t arc4random(void) { return (0x04000000); }
uint32_t arc4random_uniform(uint32_t m) { return (m ? (0x1234 % m) : 0); }
/* m_uiotombuf: build one mbuf of len bytes from the uio, advancing it. */
struct mbuf *
m_uiotombuf(struct uio *uio, int how, int len, int align, int flags)
{
	struct mbuf *m = m_get(how, MT_DATA);
	if (m == NULL) return (NULL);
	if (flags) m->m_flags |= M_PKTHDR;
	if (len > (int)sizeof(m->m_dat)) len = sizeof(m->m_dat);
	m->m_len = len;
	if (uio != NULL) uio->uio_resid -= len;
	(void)align;
	return (m);
}
void m_cat(struct mbuf *m, struct mbuf *n)
{ while (m->m_next) m = m->m_next; m->m_next = n; }
void m_copyback(struct mbuf *m, int off, int len, const void *cp)
{ (void)off; (void)cp; if (m) m->m_len = off + len; }
int sopoll_generic(struct socket *so, int e, struct thread *t)
{ (void)so; (void)t; return (e); }
int sosend_generic(struct socket *so, struct sockaddr *a, struct uio *u,
    struct mbuf *t, struct mbuf *c, int f, struct thread *td)
{ (void)so;(void)a;(void)u;(void)t;(void)c;(void)f;(void)td; return (0); }
int soreceive_generic(struct socket *so, struct sockaddr **a, struct uio *u,
    struct mbuf **m, struct mbuf **c, int *f)
{ (void)so;(void)a;(void)u;(void)m;(void)c;(void)f; return (0); }
int soreceive_stream(struct socket *so, struct sockaddr **a, struct uio *u,
    struct mbuf **m, struct mbuf **c, int *f)
{ (void)so;(void)a;(void)u;(void)m;(void)c;(void)f; return (0); }
