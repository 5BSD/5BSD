#include "kmock.h"
struct vnet _thevnet = { 0 };
struct vnet *curvnet = &_thevnet;
volatile int ticks = 0;
uint32_t arc4random(void) { return (0x04000000); }
uint32_t arc4random_uniform(uint32_t m) { return (m ? (0x1234 % m) : 0); }
struct uio *
cloneuio(struct uio *src)
{
	struct uio *dst;

	dst = calloc(1, sizeof(*dst));
	if (dst == NULL)
		return (NULL);
	*dst = *src;
	dst->uio_iov = calloc((size_t)src->uio_iovcnt, sizeof(*dst->uio_iov));
	if (dst->uio_iov == NULL) {
		kfree(dst);
		return (NULL);
	}
	memcpy(dst->uio_iov, src->uio_iov,
	    (size_t)src->uio_iovcnt * sizeof(*dst->uio_iov));
	return (dst);
}
void
freeuio(struct uio *uio)
{
	kfree(uio->uio_iov);
	kfree(uio);
}
void
uioadvance(struct uio *uio, size_t len)
{
	while (len != 0) {
		size_t n;

		if (uio->uio_iovcnt == 0)
			abort();
		n = MIN(len, uio->uio_iov->iov_len);
		uio->uio_iov->iov_base =
		    (char *)uio->uio_iov->iov_base + n;
		uio->uio_iov->iov_len -= n;
		uio->uio_resid -= (ssize_t)n;
		len -= n;
		if (uio->uio_iov->iov_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
		}
	}
}
/* m_uiotombuf: build an mbuf chain of len bytes from the uio, advancing it. */
struct mbuf *
m_uiotombuf(struct uio *uio, int how, int len, int align, int flags)
{
	struct mbuf *m, *n;
	int remaining;

	m = m_getm2(NULL, len, how, MT_DATA, flags ? M_PKTHDR : 0);
	if (m == NULL)
		return (NULL);
	remaining = len;
	for (n = m; n != NULL && remaining != 0; n = n->m_next) {
		n->m_len = MIN(remaining, MLEN);
		remaining -= n->m_len;
	}
	if ((m->m_flags & M_PKTHDR) != 0)
		m->m_pkthdr.len = len;
	if (uio != NULL)
		uio->uio_resid -= len;
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
