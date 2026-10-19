#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""
A seeded packet fuzzer for pf.  A router runs a ruleset that turns on most
of pf at once (scrub and reassembly, NAT, rdr, af-to, synproxy, modulate
state, sloppy state, block return, source tracking, pflog, pfsync), and the
test sends it malformed and unusual traffic: IP options, IPv6 extension
header chains, overlapping and out of order fragments, ICMP errors with
arbitrary inner packets, TCP options and flag combinations, SCTP chunks,
byte-flipped and truncated copies of all of these, and pfsync frames with
valid framing and arbitrary contents on the sync interface.

It passes when the router still forwards afterwards; the kernel's
INVARIANTS and WITNESS checks and the soak harness's console scan catch
the rest.  ATF variables: seed (printed when unset) and packets.
"""

import random
import struct
import subprocess
import time

import pytest
from atf_python.sys.net.tools import ToolsHelper
from atf_python.sys.net.vnet import VnetTestTemplate

PFSYNC_SIZES = {          # action: message size (struct sizes on amd64)
    0: 20,     # CLR
    2: 12,     # INS_ACK
    4: 84,     # UPD_C
    5: 12,     # UPD_REQ
    6: 264,    # DEL (pfsync_state)
    7: 12,     # DEL_C
    10: 12,    # BUS
    13: 264,   # INS
    14: 264,   # UPD
    15: 52,    # TDB
}


class TestFuzzPackets(VnetTestTemplate):
    REQUIRED_MODULES = ["pf"]
    TOPOLOGY = {
        "vnet1": {"ifaces": ["if1", "if3"]},
        "vnet2": {"ifaces": ["if1", "if2", "if3"]},
        "vnet3": {"ifaces": ["if2"]},
        "if1": {"prefixes4": [("192.0.2.2/24", "192.0.2.1/24")],
                "prefixes6": [("2001:db8::2/64", "2001:db8::1/64")]},
        "if2": {"prefixes4": [("198.51.100.1/24", "198.51.100.2/24")],
                "prefixes6": [("2001:db8:1::1/64", "2001:db8:1::2/64")]},
        "if3": {"prefixes4": [("203.0.113.2/24", "203.0.113.1/24")]},
    }

    def vnet2_handler(self, vnet):
        if1 = vnet.iface_alias_map["if1"].name
        if2 = vnet.iface_alias_map["if2"].name
        if3 = vnet.iface_alias_map["if3"].name
        ToolsHelper.print_output("/sbin/sysctl net.inet.ip.forwarding=1")
        ToolsHelper.print_output("/sbin/sysctl net.inet6.ip6.forwarding=1")
        ToolsHelper.print_output("/sbin/ifconfig pflog0 create")
        ToolsHelper.print_output("/sbin/ifconfig pfsync0 create")
        ToolsHelper.print_output(
            "/sbin/ifconfig pfsync0 syncdev %s maxupd 4 up" % if3)
        ToolsHelper.print_output("/sbin/pfctl -e")
        ToolsHelper.pf_rules([
            "set reassemble yes",
            "match in all scrub (no-df random-id max-mss 1300 reassemble tcp)",
            "match out on %s inet from 192.0.2.0/24 nat-to (%s)" % (if2, if2),
            "match out on %s inet6 from 2001:db8::/64 nat-to 2001:db8:1::1"
            % if2,
            # Last match wins: the rules for particular traffic are quick.
            "block return log",
            "pass out all",
            "pass in on %s proto pfsync" % if3,
            "pass in quick on %s inet6 to 64:ff9b::/96 af-to inet from 198.51.100.1"
            % if1,
            "pass in quick on %s inet proto tcp to port 80 rdr-to 198.51.100.2 "
            "port 8080" % if1,
            "pass in quick on %s proto tcp to port 25 synproxy state" % if1,
            "pass in quick on %s proto tcp to port 22 modulate state" % if1,
            "pass in quick on %s proto udp to port 9 keep state (sloppy)" % if1,
            "pass in quick log on %s proto tcp to port 443 keep state "
            "(source-track rule, max-src-states 50, max-src-conn 50)" % if1,
            "pass in on %s proto { icmp ipv6-icmp sctp udp tcp gre }" % if1,
            "pass in on %s inet6 proto ipv6-icmp icmp6-type "
            "{ neighbrsol, neighbradv }" % if1,
        ])

    def vnet3_handler(self, vnet):
        ToolsHelper.print_output("/sbin/route add default 198.51.100.1")
        ToolsHelper.print_output("/sbin/route add -6 default 2001:db8:1::1")

    # -- generators ------------------------------------------------------

    def rbytes(self, n):
        return bytes(self.r.getrandbits(8) for _ in range(n))

    def dst4(self):
        return self.r.choice(["198.51.100.2", "192.0.2.1", "203.0.113.1",
                              "198.51.100.1", "255.255.255.255",
                              "224.0.0.1", "0.0.0.0", "127.0.0.1",
                              "%d.%d.%d.%d" % tuple(self.r.randrange(256)
                                                   for _ in range(4))])

    def dst6(self):
        return self.r.choice(["2001:db8:1::2", "2001:db8::1", "ff02::1",
                              "64:ff9b::c633:6402", "64:ff9b::c000:201",
                              "::1", "fe80::1", "::",
                              "2001:db8:1::%x" % self.r.randrange(65536)])

    def tcp(self):
        sp = self.sp
        opts = []
        for _ in range(self.r.randrange(5)):
            opts.append(self.r.choice([
                ("MSS", self.r.randrange(65536)),
                ("WScale", self.r.randrange(256)),
                ("SAckOK", b""),
                ("SAck", tuple(self.r.randrange(2 ** 32)
                               for _ in range(2 * self.r.randrange(1, 5)))),
                ("Timestamp", (self.r.randrange(2 ** 32),
                               self.r.randrange(2 ** 32))),
                ("NOP", None), ("EOL", None),
                (self.r.randrange(256), self.rbytes(self.r.randrange(8))),
            ]))
        return sp.TCP(sport=self.r.choice([1024, 40000, self.r.randrange(65536)]),
                      dport=self.r.choice([80, 25, 22, 443, 9, 8080,
                                           self.r.randrange(65536)]),
                      flags=self.r.randrange(256),
                      seq=self.r.randrange(2 ** 32), ack=self.r.randrange(2 ** 32),
                      window=self.r.randrange(65536), options=opts) / \
            self.rbytes(self.r.choice([0, 0, 1, 40, 600]))

    def l4(self, v6):
        sp = self.sp
        c = self.r.randrange(9)
        if c == 0:
            return self.tcp()
        if c == 1:
            return sp.UDP(sport=self.r.randrange(65536),
                          dport=self.r.choice([9, 53, 123, 4500,
                                               self.r.randrange(65536)])) / \
                self.rbytes(self.r.randrange(64))
        if c == 2:
            # an ICMP error around an arbitrary inner packet
            inner = self.inner(v6)
            if v6:
                return self.r.choice([sp.ICMPv6DestUnreach(code=self.r.randrange(8)),
                                      sp.ICMPv6PacketTooBig(mtu=self.r.randrange(2000)),
                                      sp.ICMPv6TimeExceeded(),
                                      sp.ICMPv6ParamProblem(ptr=self.r.randrange(80))]) / inner
            return sp.ICMP(type=self.r.choice([3, 4, 5, 11, 12]),
                           code=self.r.randrange(16)) / inner
        if c == 3:
            if v6:
                return sp.ICMPv6EchoRequest(id=self.r.randrange(65536)) / \
                    self.rbytes(self.r.randrange(64))
            return sp.ICMP(type=self.r.randrange(256), code=self.r.randrange(256),
                           id=self.r.randrange(65536)) / \
                self.rbytes(self.r.randrange(64))
        if c == 4:
            chunks = []
            for _ in range(self.r.randrange(1, 4)):
                chunks.append(self.r.choice([
                    sp.SCTPChunkInit(init_tag=self.r.randrange(2 ** 32),
                                     n_in_streams=1, n_out_streams=1,
                                     a_rwnd=1500),
                    sp.SCTPChunkInitAck(init_tag=self.r.randrange(2 ** 32)),
                    sp.SCTPChunkAbort(), sp.SCTPChunkShutdown(),
                    sp.SCTPChunkCookieEcho(cookie=self.rbytes(8)),
                    sp.SCTPChunkHeartbeatReq(),
                    sp.SCTPChunkData(data=self.rbytes(16)),
                    sp.Raw(struct.pack("!BBH", self.r.choice([0xc1, 0x80, 0xc0,
                                                              self.r.randrange(256)]),
                                       self.r.randrange(256), 8) + self.rbytes(4)),
                ]))
            pkt = sp.SCTP(sport=self.r.randrange(65536),
                          dport=self.r.randrange(65536),
                          tag=self.r.choice([0, self.r.randrange(2 ** 32)]))
            for ch in chunks:
                pkt = pkt / ch
            return pkt
        if c == 5 and v6:
            return self.r.choice([sp.ICMPv6ND_NS(tgt=self.dst6()),
                                  sp.ICMPv6ND_NA(tgt=self.dst6(), R=0, S=1),
                                  sp.ICMPv6ND_RS(), sp.ICMPv6ND_Redirect(),
                                  sp.ICMPv6MLQuery(), sp.ICMPv6MLReport()])
        if c == 6:
            return sp.GRE(proto=self.r.choice([0x0800, 0x86dd, 0x6558])) / \
                self.rbytes(self.r.randrange(40))
        return sp.Raw(self.rbytes(self.r.randrange(80)))

    def inner(self, v6):
        sp = self.sp
        if v6:
            ip = sp.IPv6(src=self.r.choice(["2001:db8:1::2", "2001:db8::2",
                                            "64:ff9b::c633:6402"]),
                         dst=self.dst6(), nh=self.r.choice([6, 17, 58, 132, 44]))
        else:
            ip = sp.IP(src=self.r.choice(["198.51.100.2", "192.0.2.2",
                                          "198.51.100.1"]),
                       dst=self.dst4(), proto=self.r.choice([6, 17, 1, 132]),
                       frag=self.r.choice([0, 0, 0, self.r.randrange(8192)]))
        body = self.rbytes(self.r.choice([0, 4, 8, 20]))
        return sp.Raw(bytes(ip)[:self.r.choice([8, 20, 40, 60])] + body)

    def ext6(self):
        sp = self.sp
        hdrs = []
        for _ in range(self.r.randrange(4)):
            hdrs.append(self.r.choice([
                sp.IPv6ExtHdrHopByHop(options=[sp.RouterAlert(value=0)]
                                      if self.r.randrange(2) else
                                      [sp.PadN(optdata=self.rbytes(self.r.randrange(6)))]),
                sp.IPv6ExtHdrDestOpt(options=[sp.Jumbo(jumboplen=self.r.randrange(2 ** 32))]
                                     if self.r.randrange(4) == 0 else []),
                sp.IPv6ExtHdrRouting(type=self.r.choice([0, 2, 4, self.r.randrange(256)]),
                                     segleft=self.r.randrange(4),
                                     addresses=[self.dst6()]),
                sp.IPv6ExtHdrFragment(offset=self.r.randrange(8192),
                                      m=self.r.randrange(2),
                                      id=self.r.randrange(2 ** 32)),
                sp.AH(spi=self.r.randrange(2 ** 32)),
            ]))
        return hdrs

    def packet(self):
        sp = self.sp
        v6 = self.r.randrange(2) == 1
        if v6:
            ip = sp.IPv6(src=self.r.choice(["2001:db8::2", "2001:db8::3",
                                            "fe80::2", "::"]),
                         dst=self.dst6(), hlim=self.r.choice([1, 2, 64, 255]),
                         fl=self.r.randrange(2 ** 20))
            for h in self.ext6():
                ip = ip / h
        else:
            opts = []
            if self.r.randrange(4) == 0:
                opts = [self.r.choice([sp.IPOption_RR(),
                                       sp.IPOption_LSRR(routers=["198.51.100.2"]),
                                       sp.IPOption_Timestamp(),
                                       sp.IPOption_Router_Alert(),
                                       sp.IPOption(self.rbytes(4))])]
            ip = sp.IP(src=self.r.choice(["192.0.2.2", "192.0.2.3", "0.0.0.0"]),
                       dst=self.dst4(), ttl=self.r.choice([0, 1, 2, 64]),
                       flags=self.r.randrange(8), id=self.r.randrange(65536),
                       tos=self.r.randrange(256), options=opts)
        pkt = ip / self.l4(v6)
        if self.r.randrange(6) == 0:
            # fragments: shuffled, duplicated, overlapping
            try:
                if v6:
                    big = sp.IPv6(src="2001:db8::2", dst=self.dst6()) / \
                        sp.IPv6ExtHdrFragment(id=self.r.randrange(2 ** 32)) / \
                        self.l4(True) / self.rbytes(self.r.randrange(200, 3000))
                    frags = sp.fragment6(big, self.r.choice([72, 120, 512, 1280]))
                else:
                    frags = sp.fragment(pkt / self.rbytes(self.r.randrange(600)),
                                        self.r.choice([8, 16, 64, 512]))
            except Exception:
                frags = [pkt]
            frags = list(frags)
            self.r.shuffle(frags)
            if frags and self.r.randrange(2):
                frags.append(frags[0])
            return frags
        return [pkt]

    def flow(self):
        """A TCP connection attempt to a port with stateful options, then
        segments that follow it more or less closely."""
        sp = self.sp
        v6 = self.r.randrange(3) == 0
        dport = self.r.choice([25, 80, 22, 443])
        sport = self.r.randrange(1024, 65536)
        seq = self.r.randrange(2 ** 32)
        ip = sp.IPv6(src="2001:db8::2", dst="2001:db8:1::2") if v6 else \
            sp.IP(src="192.0.2.2", dst="198.51.100.2")
        opts = [("MSS", 1460), ("SAckOK", b""), ("WScale", self.r.randrange(15)),
                ("Timestamp", (self.r.randrange(2 ** 32), 0))]
        pkts = [ip / sp.TCP(sport=sport, dport=dport, flags="S", seq=seq,
                            options=opts)]
        for _ in range(self.r.randrange(1, 8)):
            pkts.append(ip / sp.TCP(
                sport=sport, dport=dport,
                flags=self.r.choice(["A", "PA", "FA", "R", "RA", "SA", "S",
                                     self.r.randrange(256)]),
                seq=seq + 1 + self.r.choice([0, 0, 1, -1, 65536, 2 ** 31]),
                ack=self.r.randrange(2 ** 32),
                window=self.r.randrange(65536),
                options=self.r.choice([[], opts[3:],
                                       [("SAck", (seq, seq + 10))]])) /
                self.rbytes(self.r.choice([0, 10, 1000])))
        return pkts

    def mutate(self, raw):
        b = bytearray(raw)
        for _ in range(self.r.randrange(1, 6)):
            if not b:
                break
            c = self.r.randrange(3)
            i = self.r.randrange(len(b))
            if c == 0:
                b[i] = self.r.randrange(256)
            elif c == 1:
                del b[i:]
            else:
                b[i:i] = self.rbytes(self.r.randrange(1, 8))
        return bytes(b)

    def pfsync(self):
        sp = self.sp
        body = b""
        for _ in range(self.r.randrange(1, 4)):
            action = self.r.choice(list(PFSYNC_SIZES) + [1, 3, 8, 9, 11, 12, 16,
                                                         self.r.randrange(256)])
            size = PFSYNC_SIZES.get(action, 4 * self.r.randrange(1, 20))
            count = self.r.choice([0, 1, 2, 3, self.r.randrange(65536)])
            dw = size // 4 if self.r.randrange(4) else self.r.randrange(256)
            msgs = self.rbytes(size * min(count, 3))
            body += struct.pack("!BBH", action, dw, count) + msgs
        version = 6 if self.r.randrange(8) else self.r.randrange(256)
        length = 20 + len(body)
        if self.r.randrange(6) == 0:
            length = self.r.randrange(65536)
        hdr = struct.pack("!BBH", version, 0, length) + bytes(16)
        return sp.IP(dst="224.0.0.240", src="203.0.113.2", ttl=255, proto=240) / \
            sp.Raw(hdr + body)

    # -- the test --------------------------------------------------------

    def ping(self, addr):
        return subprocess.run(["/sbin/ping", "-c", "3", "-t", "10", addr],
                              stdout=subprocess.DEVNULL).returncode

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["scapy"])
    def test_fuzz(self):
        import scapy.all as sp
        import scapy.contrib.igmp  # noqa: F401
        self.sp = sp
        if1 = self.vnet.iface_alias_map["if1"].name
        if3 = self.vnet.iface_alias_map["if3"].name
        ToolsHelper.print_output("/sbin/route add default 192.0.2.1")
        ToolsHelper.print_output("/sbin/route add -6 default 2001:db8::1")
        assert self.ping("198.51.100.2") == 0

        v = self.atf_vars
        seed = int(v.get("seed", str(int(time.time() * 1000) & 0xffffffff)))
        count = int(v.get("packets", "6000"))
        print("seed %d packets %d" % (seed, count))
        self.r = random.Random(seed)
        gw = self.vnet.iface_alias_map["if1"].epairb.ether
        sync_gw = self.vnet.iface_alias_map["if3"].epairb.ether

        s1 = sp.conf.L2socket(iface=if1)
        s3 = sp.conf.L2socket(iface=if3)
        sent = 0
        while sent < count:
            c = self.r.randrange(10)
            if c == 0:
                try:
                    s3.send(sp.Ether(dst=sync_gw) / self.pfsync())
                except Exception:
                    pass
                sent += 1
                continue
            try:
                pkts = self.flow() if c in (2, 3) else self.packet()
            except Exception:
                continue	# scapy cannot build this one; not pf's business
            for p in pkts:
                try:
                    eth = sp.Ether(dst=gw,
                                   type=0x86dd if p.haslayer(sp.IPv6) else 0x800)
                    frame = bytes(eth / p)
                except Exception:
                    continue
                if c == 1:
                    frame = frame[:14] + self.mutate(frame[14:])
                try:
                    s1.send(sp.Raw(frame))
                except OSError:
                    pass
                sent += 1
            if sent % 1000 < 5:
                print("sent %d" % sent)
        s1.close()
        s3.close()

        # The router still forwards, and pf still answers.
        time.sleep(2)
        assert self.ping("198.51.100.2") == 0
