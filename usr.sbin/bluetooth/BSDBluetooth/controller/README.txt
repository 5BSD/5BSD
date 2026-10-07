5BSD Bluetooth controller broker

Bluetooth.cap contains the unprivileged blued unit and a small controller unit.
The controller unit runs as root, already in capability mode, solely to create
raw HCI sockets whose kernel PCB carries the raw-HCI privilege. The daemon
obtains an already-bound descriptor through system.Bluetooth.Controller.
Both units need the updated libbluetooth: HCI node addresses use bindat and
connectat with the socket descriptor, retaining socket-rights and MAC checks.
They also require the updated ng_btsocket kernel module: HCI and SEQPACKET
L2CAP opt into PR_CAPATTACH. HCI raw-command privilege remains checked at
socket creation; an unprivileged sandbox does not gain it from this flag.

SwitchBoard requires system.bluetooth.controller before endpoint admission.
The controller additionally checks BLUED_CONTROLLER_OPEN in the stamped
session rights, including at the operation boundary. Requests cannot supply
their own identity or rights. Exactly one bounded, named-controller request is
accepted per session; malformed messages and attachments fail closed.

The delivered socket has read/write, event, socket-option, fstat, fcntl and
ioctl rights. Only GET_CON_LIST and NODE_INIT ioctls are allowed. It cannot be
rebound or connected to another controller. Transfer is allowed once; the
client then disables further transfers. Fork and exec inheritance are locked.
Raw HCI access permits controller commands and is intentionally a privileged
surface, separate from ordinary application access to system.Bluetooth.

The provider uses bounded nonblocking channel sessions with two-second
deadlines. It does not create a privileged process per client. The source
keeps the reply channel until peer close or expiry, allowing synchronous
clients to consume the reply before EOF. Supervisor loss stops the broker.
The source tests use real capability channels and socket descriptors, replacing the HCI
socket opener with a socketpair so software checks do not need a controller.
Real HCI operation still requires the Bluetooth kernel modules and a virtual
or physical controller. Do not count the socketpair tests as radio validation.
