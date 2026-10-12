#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise real adapters against native IPv4/IPv6 fragment ownership semantics."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[4] / 'sys/netpfil/openbsd-pf/openbsd_net.c'

STUBS = r'''
#include <sys/types.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
struct mbuf { struct mbuf *m_nextpkt; int freed;
    struct { unsigned int csum_flags; } m_pkthdr; } packets[3];
struct mbuf_list { struct mbuf *items[3]; int count; };
struct ip6_frag { char bytes[8]; };
static int mode, calls;
static void ml_init(struct mbuf_list *ml) { memset(ml, 0, sizeof(*ml)); }
static void ml_enqueue(struct mbuf_list *ml, struct mbuf *m) {
    assert(!m->freed && m->m_nextpkt == NULL);
    ml->items[ml->count++] = m;
}
static void m_freem(struct mbuf *m) {
    assert(!m->freed);
    m->freed = 1;
}
static unsigned int ip6_randomid(void) { return 123; }
/* Native contract: original survives; completed/partial fragments follow it. */
static int ip6_fragment(void *ifp, struct mbuf *m, int hlen,
    u_char proto, int len, unsigned int id) {
    assert(ifp == NULL && m == &packets[0]);
    assert(hlen == 40 && proto == 58 && len == 16 && id == htonl(123));
    calls++;
    if (mode != 1) m->m_nextpkt = &packets[1];
    if (mode == 0 || mode == 3) packets[1].m_nextpkt = &packets[2];
    return mode == 0 ? 0 : ENOBUFS;
}
'''
CHECKS = r'''
int main(void) {
    struct mbuf_list ml;
    for (mode = 0; mode < 4; mode++) {
        memset(packets, 0, sizeof(packets)); calls = 0;
        int rc = obsd_ip6_fragment(&packets[0], &ml, 40, 58, 64);
        assert(calls == 1 && packets[0].freed);
        if (mode == 0) {
            assert(rc == 0 && ml.count == 2);
            assert(ml.items[0] == &packets[1] && ml.items[1] == &packets[2]);
            assert(!packets[1].freed && !packets[2].freed);
        } else {
            assert(rc == ENOBUFS && ml.count == 0);
            assert(packets[1].freed == (mode != 1));
            assert(packets[2].freed == (mode == 3));
        }
    }
    /* OpenBSD rejects a payload smaller than eight before calling native code. */
    memset(packets, 0, sizeof(packets)); calls = 0;
    assert(obsd_ip6_fragment(&packets[0], &ml, 40, 58, 55) == EMSGSIZE);
    assert(calls == 0 && packets[0].freed && ml.count == 0);
    return 0;
}
'''


IPV4_STUBS = r'''
struct ip { char unused; };
struct ifnet { unsigned long if_hwassist; };
#define mtod(m, type) ((type)(m))
#define CSUM_IP 1
static void in_proto_cksum_out(struct mbuf *m, void *inp) {
    assert(m == &packets[0] && inp == NULL);
}
static int ip_fragment(struct ip *ip, struct mbuf **m, int mtu,
    unsigned long hwassist) {
    assert((void *)ip == (void *)&packets[0] && *m == &packets[0]);
    assert(mtu == 64 && hwassist == 0 && ((*m)->m_pkthdr.csum_flags & CSUM_IP));
    calls++;
    if (mode != 1) (*m)->m_nextpkt = &packets[1];
    if (mode == 0 || mode == 3) packets[1].m_nextpkt = &packets[2];
    return mode == 0 ? 0 : ENOBUFS;
}
'''
IPV4_CHECKS = r'''
int main(void) {
    struct mbuf_list ml; struct ifnet ifp = {0};
    for (mode = 0; mode < 4; mode++) {
        memset(packets, 0, sizeof(packets)); calls = 0;
        int rc = obsd_ip_fragment(&packets[0], &ml, &ifp, 64);
        assert(calls == 1);
        if (mode == 0) {
            assert(rc == 0 && ml.count == 3);
            for (int i = 0; i < 3; i++)
                assert(ml.items[i] == &packets[i] && !packets[i].freed);
        } else {
            assert(rc == ENOBUFS && ml.count == 0 && packets[0].freed);
            assert(packets[1].freed == (mode != 1));
            assert(packets[2].freed == (mode == 3));
        }
    }
    return 0;
}
'''

def adapter(source, name="obsd_ip6_fragment"):
    text = source.read_text()
    start = text.index('int\n' + name + '(')
    end = text.index('\n#endif' if name == 'obsd_ip6_fragment' else '\n#ifdef INET6', start)
    return text[start:end]


class FragmentContractTests(unittest.TestCase):
    def check_contract(self, name, stubs, checks):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            c = path / 'contract.c'
            c.write_text(stubs + adapter(SOURCE, name) + checks)
            subprocess.run(shlex.split(os.environ.get('CC', 'cc')) +
                           ['-Wall', '-Wextra', '-Werror', str(c), '-o', str(path / 'contract')],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(path / 'contract')], check=True,
                           capture_output=True, text=True, cwd=path)

    def test_original_partial_chain_and_minimum_payload(self):
        self.check_contract('obsd_ip6_fragment', STUBS, CHECKS)

    def test_ipv4_retains_first_fragment_and_frees_partial_chains(self):
        # IPv4 retains the original as its valid first fragment, unlike IPv6.
        stubs = STUBS[:STUBS.index('static unsigned int ip6_randomid')]
        self.check_contract('obsd_ip_fragment', stubs + IPV4_STUBS, IPV4_CHECKS)


if __name__ == '__main__':
    unittest.main()
