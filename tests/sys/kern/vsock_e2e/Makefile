# VirtIO end-to-end (host <-> bhyve guest) test harness.  The historical
# directory name predates the RNG and input coverage.
#
# Installed with the complete WASPNest qualification package under
# ${TESTSBASE}/sys/kern/vsock_e2e.  Unlike the ATF suites in the parent
# directory these are NOT run by kyua automatically: they require a bhyve host
# with a running guest and are driven by run.sh.  See the header of run.sh for
# the environment it expects.
#
# Host-side tools (built and installed here):
#   unix-pipe       AF_UNIX netcat (relay/echo/drain) for the device's
#                   path= directory -- the host end of the vsock device.
#   vsh-connect     capability-mode host->guest connector via the device
#                   control socket (SCM_RIGHTS fd relay).
#
# Guest-side tools (vsock-pipe, vsock-conntest) live here as sources too
# so a 5BSD guest image build can compile them; they use <sys/vsock.h>
# which only the guest kernel provides at runtime, so they are shipped as
# source, not built here.

PACKAGE=	waspnest-tests
TESTSDIR=	${TESTSBASE}/sys/kern/vsock_e2e
BINDIR=		${TESTSDIR}
SCRIPTSDIR=	${TESTSDIR}

WARNS?=		3
MAN=

# Host-side helper programs.
PROGS+=		unix-pipe
PROGS+=		vsock-pipe
PROGS+=		vsh-connect
PROGS+=		vsh-connect-test-server
PROGS+=		uinput-inject
PROGS+=		freebsd-input-check
NO_SHARED.freebsd-input-check=	yes
PROGS+=		freebsd-tpm2-check
NO_SHARED.freebsd-tpm2-check=	yes
PROGS+=		freebsd-fwcfg-check
NO_SHARED.freebsd-fwcfg-check=	yes
PROGS+=		wdfire
NO_SHARED.wdfire=	yes
PROGS+=		vtcryptocbc
NO_SHARED.vtcryptocbc=	yes
PROGS+=		gpu-rfb-check
NO_SHARED.gpu-rfb-check=	yes

# Driver scripts (keep the .sh suffix; SCRIPTS strips it by default).
# run.sh drives a 5BSD guest; run-linux.sh drives a Linux guest via gvsock.py.
SCRIPTS+=	run.sh
SCRIPTSNAME_run.sh=	run.sh
SCRIPTS+=	run-linux.sh
SCRIPTSNAME_run-linux.sh=	run-linux.sh
SCRIPTS+=	run-alpine-bhyve.sh
SCRIPTSNAME_run-alpine-bhyve.sh=	run-alpine-bhyve.sh
SCRIPTS+=	run-alpine-auto.sh
SCRIPTSNAME_run-alpine-auto.sh=	run-alpine-auto.sh
SCRIPTS+=	run-alpine-no-msix.sh
SCRIPTSNAME_run-alpine-no-msix.sh=	run-alpine-no-msix.sh
SCRIPTS+=	run-alpine-matrix.sh
SCRIPTSNAME_run-alpine-matrix.sh=	run-alpine-matrix.sh
SCRIPTS+=	run-alpine-multi-vsock.sh
SCRIPTSNAME_run-alpine-multi-vsock.sh=	run-alpine-multi-vsock.sh
SCRIPTS+=	run-5bsd-auto.sh
SCRIPTSNAME_run-5bsd-auto.sh=	run-5bsd-auto.sh
SCRIPTS+=	run-freebsd-vtrnd-reset.sh
SCRIPTSNAME_run-freebsd-vtrnd-reset.sh=	run-freebsd-vtrnd-reset.sh
SCRIPTS+=	acmd-console.sh
SCRIPTSNAME_acmd-console.sh=	acmd-console.sh
SCRIPTS+=	acmd-ssh.sh
SCRIPTSNAME_acmd-ssh.sh=	acmd-ssh.sh
SCRIPTS+=	alpine-guest-setup.sh
SCRIPTSNAME_alpine-guest-setup.sh=	alpine-guest-setup.sh
SCRIPTS+=	host-tools-selftest.sh
SCRIPTSNAME_host-tools-selftest.sh=	host-tools-selftest.sh
SCRIPTS+=	virtio-host-regression.sh
SCRIPTSNAME_virtio-host-regression.sh=	virtio-host-regression.sh
SCRIPTS+=	build-5bsd-virtio-modules.sh
SCRIPTSNAME_build-5bsd-virtio-modules.sh=	build-5bsd-virtio-modules.sh
SCRIPTS+=	build-vmm-module.sh
SCRIPTSNAME_build-vmm-module.sh=	build-vmm-module.sh
SCRIPTS+=	run-kernel-contract-root.sh
SCRIPTSNAME_run-kernel-contract-root.sh=	run-kernel-contract-root.sh
SCRIPTS+=	virtio-lab.lua
SCRIPTSNAME_virtio-lab.lua=	virtio-lab
SCRIPTS+=	virtio-lab-selftest.sh
SCRIPTSNAME_virtio-lab-selftest.sh=	virtio-lab-selftest.sh
SCRIPTS+=	virtio-lab-probe.sh
SCRIPTSNAME_virtio-lab-probe.sh=	virtio-lab-probe.sh
SCRIPTS+=	virtio-lab-case.sh
SCRIPTSNAME_virtio-lab-case.sh=	virtio-lab-case.sh
SCRIPTS+=	run-waspnest-qualification.sh
SCRIPTSNAME_run-waspnest-qualification.sh=	run-waspnest-qualification.sh
SCRIPTS+=	virtio-ring-trace.sh
SCRIPTSNAME_virtio-ring-trace.sh=	virtio-ring-trace.sh

# Guest-side tool sources (shipped for in-guest compilation / use).  Use the
# ${PACKAGE}FILES filegroup that bsd.test.mk wires into the test package
# (FILESDIR=${TESTSDIR}, FILESPACKAGE=${PACKAGE}); a plain FILES+= is not
# packaged with the test.
${PACKAGE}FILES+=	vsock-pipe.c
${PACKAGE}FILES+=	vsock-conntest.c
${PACKAGE}FILES+=	vsock-recrx.c
${PACKAGE}FILES+=	gvsock.py
${PACKAGE}FILES+=	gvirtio_features.py
${PACKAGE}FILES+=	ginput.py
${PACKAGE}FILES+=	grng.py
${PACKAGE}FILES+=	gballoon.py
${PACKAGE}FILES+=	grtc.py
${PACKAGE}FILES+=	gblock.py
${PACKAGE}FILES+=	gnet.py
${PACKAGE}FILES+=	gnonvirtio.py
${PACKAGE}FILES+=	freebsd-nonvirtio.sh
${PACKAGE}FILES+=	freebsd-fwcfg-check.c
${PACKAGE}FILES+=	wdfire.c
${PACKAGE}FILES+=	vtcryptocbc.c
${PACKAGE}FILES+=	gscsi.py
${PACKAGE}FILES+=	gconsole.py
${PACKAGE}FILES+=	g9p.py
${PACKAGE}FILES+=	ggpu.py
${PACKAGE}FILES+=	gmem.py
${PACKAGE}FILES+=	giommu.py
${PACKAGE}FILES+=	gsnd.py
${PACKAGE}FILES+=	gpmem.py
${PACKAGE}FILES+=	ALPINE.md
${PACKAGE}FILES+=	FIVEBSD.md
${PACKAGE}FILES+=	FRAMEWORK.md
${PACKAGE}FILES+=	virtio-lab.yaml

.include <bsd.test.mk>
