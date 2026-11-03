# SPDX-License-Identifier: BSD-2-Clause
"""Decode private PCAP files without opening a live capture interface."""
import ipaddress
import argparse
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


def pcap(packet):
    return (struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) +
            struct.pack('<IIII', 0, 0, len(packet), len(packet)) + packet)


def udp():
    return struct.pack('!HHHH', 11111, 22222, 13, 0) + b'hello'


def ethernet(protocol, payload):
    return bytes.fromhex('020000000002020000000001') + struct.pack('!H', protocol) + payload


def ipv4():
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 33, 0, 0, 64, 17, 0,
                         ipaddress.ip_address('192.0.2.1').packed,
                         ipaddress.ip_address('198.51.100.2').packed)
    total = sum(struct.unpack('!10H', header))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    header = header[:10] + struct.pack('!H', (~total) & 0xffff) + header[12:]
    return ethernet(0x0800, header + udp())


def ipv6():
    header = struct.pack('!IHBB16s16s', 6 << 28, 13, 17, 64,
                         ipaddress.ip_address('2001:db8::1').packed,
                         ipaddress.ip_address('2001:db8::2').packed)
    return ethernet(0x86dd, header + udp())


def program_environment():
    parser = argparse.ArgumentParser()
    parser.add_argument('--program-runtime', nargs='+', required=True)
    args, unittest_args = parser.parse_known_args()
    sys.argv[1:] = unittest_args
    libraries = {Path(path).resolve(strict=True) for path in args.program_runtime}
    environment = dict(os.environ)
    environment.pop('LD_PRELOAD', None)
    environment['LD_LIBRARY_PATH'] = ':'.join(sorted({str(path.parent) for path in libraries}))
    return environment, libraries


PROGRAM_ENVIRONMENT, PROGRAM_LIBRARIES = program_environment()


class OfflineTest(unittest.TestCase):
    def test_declared_program_libraries(self):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        environment = dict(PROGRAM_ENVIRONMENT, LD_TRACE_LOADED_OBJECTS='1',
                           LD_TRACE_LOADED_OBJECTS_FMT1='%o|%p\\n',
                           LD_TRACE_LOADED_OBJECTS_FMT2='%o|%p\\n')
        result = subprocess.run([str(root / 'usr.sbin/tcpdump/tcpdump/tcpdump')], env=environment,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        paths = []
        for line in result.stdout.splitlines():
            name, path = line.split('|')
            if name == path == '[vdso]':
                continue
            loaded = Path(path).resolve(strict=True)
            self.assertIn(loaded, PROGRAM_LIBRARIES)
            paths.append(loaded)
        self.assertTrue(paths)

    def run_capture(self, content, *filters):
        root = Path(os.environ['TEST_SRCDIR']) / os.environ['TEST_WORKSPACE']
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / 'input.pcap'
            capture.write_bytes(content)
            result = subprocess.run([str(root / 'usr.sbin/tcpdump/tcpdump/tcpdump'),
                '-n', '-t', '-r', str(capture), *filters], cwd=temporary,
                env=PROGRAM_ENVIRONMENT, capture_output=True, text=True, timeout=15)
            self.assertEqual(sorted(p.name for p in Path(temporary).iterdir()), ['input.pcap'])
            self.assertEqual(capture.read_bytes(), content)
            return result

    def test_ipv4_udp_decode(self):
        result = self.run_capture(pcap(ipv4()), 'udp')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('192.0.2.1.11111', result.stdout)
        self.assertIn('198.51.100.2.22222', result.stdout)
        self.assertIn('udp 5', result.stdout)

    def test_ipv6_udp_decode(self):
        result = self.run_capture(pcap(ipv6()), 'udp')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('2001:db8::1', result.stdout)
        self.assertIn('2001:db8::2', result.stdout)
        self.assertIn('udp 5', result.stdout)

    def test_compiled_filter_excludes_packet(self):
        result = self.run_capture(pcap(ipv4()), 'tcp')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')

    def test_truncated_ethernet_does_not_crash(self):
        result = self.run_capture(pcap(b'\x00' * 6))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('[|ether]', result.stdout)

    def test_invalid_capture_is_rejected(self):
        result = self.run_capture(b'not a pcap file')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('tcpdump:', result.stderr)


if __name__ == '__main__':
    unittest.main()
