5BSD PF state capability

system.Network.PF is provided by Network.cap's pf unit (BSDPF). It is separate
from the unprivileged network connection/resolver daemon. switchboard requires
the system.network.pf.read anointment before admission. The provider additionally
requires session right PF_MONITOR_RIGHT_READ, preserving rights attenuation.

Each connection accepts one pf_monitor_message with PF_MONITOR_MAGIC and error
zero, without attachments. The reply has the same magic, a positive errno on
failure, and exactly one descriptor on success. The descriptor is /dev/pf opened
read-only relative to the supplied /dev directory; it carries READ, FSTAT and
IOCTL, with only state export v2 allowed. It is hardened against fork/exec and
can be transferred once to the client. The client must narrow transfer rights
again before use and close it after the snapshot. No rules or state mutation
operation is exposed. Client wait/flush deadlines bound stalled connections.

The state export v2 ioctl depends on the kernel's compatibility support. It
cannot represent every modern cross-family NAT detail. Unsupported kernels
fail the operation; clients must not silently fall back to global privileged
access. A future versioned structured/netlink backend can remove this ABI
limitation while retaining this narrow admission boundary.

Build/install this subdirectory through BSDNetwork's regular build so it stays
in the bsdnetwork package. This service requires no GUI/application installation.
