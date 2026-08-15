#!/bin/sh
#
# Run the complete WASPNest VirtIO qualification gate.  virtio-lab owns
# per-case logs, resumability, cleanup, collision-free VM allocation, and the
# machine-readable result summary under WORKDIR.
#
# Profile-dependent inputs:
#   UPLINK=host-interface
#     Required by profiles that select Alpine networked VM cases.  Nested-only
#     profiles do not prepare or alter host networking.
#   ISO=/path/to/alpine-virt.iso
#     Required by profiles that select Alpine VM cases.
#   FIVEBSD_IMAGE=/path/to/disposable-freebsd.raw
#     Required by profiles that select a 5BSD VM case.  Nested-only profiles
#     instead use the NESTED_* inputs below and must not need an unrelated
#     disposable 5BSD image.
#
# Optional:
#   PROFILE=qualification|soak-smoke  JOBS=3  BRIDGE=bridge0  RESUME=no
#   PLAN_ONLY=yes  validate and print the exact virtio-lab invocation without
#                  requiring root or changing host state
#   VIRTIO_REFERENCE_ARTIFACT_DIR=/path/to/complete-pinned-corpus
#   SOUND_PLAY=/dev/dsp SOUND_RECORD=/dev/dsp
#   Intel hardware promotion uses PROFILE=intel-qualification and requires
#   the NESTED_L1_* and NESTED_*_L2_IMAGE inputs documented by
#   run-vmx-nested-live.sh.
#   PROFILE=full-qualification adds both the nested and representative OSS
#   audio/checkpoint gates to the complete portable qualification matrix.
#   WORKDIR=/tmp/virtio-qualification
#

set -eu

PROFILE=${PROFILE:-qualification}
JOBS=${JOBS:-3}
BRIDGE=${BRIDGE:-bridge0}
RESUME=${RESUME:-no}
PLAN_ONLY=${PLAN_ONLY:-no}
WORKDIR=${WORKDIR:-/tmp/virtio-qualification}
SRCTOP=${SRCTOP:-/usr/src}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "${LAB+x}" ]; then
	if [ -f "$SRCTOP/tests/sys/kern/vsock_e2e/virtio-lab.lua" ]; then
		LAB=$SRCTOP/tests/sys/kern/vsock_e2e/virtio-lab.lua
	else
		LAB=$SCRIPT_DIR/virtio-lab
	fi
fi
if [ ! -f "$LAB" ]; then
	echo "virtio-lab not found: $LAB" >&2
	exit 1
fi

# The metadata-only corpus gate is always run by host-regression.  When an
# operator supplies the optional local artifacts, authenticate the complete
# pinned set before creating a bridge, starting a VM, or allocating any
# qualification state.  Do not pass this host-only path to VM workers.
if [ -n "${VIRTIO_REFERENCE_ARTIFACT_DIR:-}" ]; then
	REFERENCE_VALIDATOR=$SRCTOP/tests/sys/kern/vsock_device_harness/validate-virtio-reference-corpus.sh
	REFERENCE_CATALOG=$SRCTOP/tests/sys/kern/vsock_device_harness/virtio-reference-corpus.tsv
	if [ ! -f "$REFERENCE_VALIDATOR" ] || [ ! -f "$REFERENCE_CATALOG" ]; then
		echo "VirtIO reference corpus validator is unavailable under $SRCTOP" >&2
		exit 1
	fi
	sh "$REFERENCE_VALIDATOR" "$REFERENCE_CATALOG" --waspnest \
	    "$VIRTIO_REFERENCE_ARTIFACT_DIR"
fi

case "$PROFILE" in
qualification|intel-qualification|audio-qualification|full-qualification|release|checkpoint|soak|soak-smoke|audio|checkpoint-audio|nested|nested-default)
	;;
*)
	echo "unsupported qualification profile: $PROFILE" >&2
	exit 1
	;;
esac

# Keep this front-end's prerequisites aligned with virtio-lab's selected
# executors.  In particular, the nested profiles contain VM-free build gates
# and an externally driven L1/L2 qualification case, not an Alpine or
# fivebsd-auto case.  Passing absent optional inputs through to virtio-lab
# would also make the saved resume configuration depend on irrelevant paths.
case "$PROFILE" in
qualification|intel-qualification|full-qualification|release)
	: "${UPLINK:?set UPLINK to the host network interface}"
	: "${ISO:?set ISO to an Alpine virt ISO}"
	: "${FIVEBSD_IMAGE:?set FIVEBSD_IMAGE to a disposable FreeBSD image}"
	;;
checkpoint|soak|soak-smoke|audio|checkpoint-audio|audio-qualification)
	: "${UPLINK:?set UPLINK to the host network interface}"
	: "${ISO:?set ISO to an Alpine virt ISO}"
	;;
nested|nested-default)
	;;
esac
case "$JOBS" in
''|*[!0-9]*|0)
	echo "JOBS must be a positive integer" >&2
	exit 1
	;;
esac
case "$RESUME" in
yes|no)
	;;
*)
	echo "RESUME must be yes or no" >&2
	exit 1
	;;
esac
case "$PLAN_ONLY" in
yes|no)
	;;
*)
	echo "PLAN_ONLY must be yes or no" >&2
	exit 1
	;;
esac
if [ "$PLAN_ONLY" = no ] && [ "$(id -u)" -ne 0 ]; then
	echo "run-waspnest-qualification.sh must run as root" >&2
	exit 1
fi

set -- /usr/libexec/flua "$LAB" run \
    --profile "$PROFILE" --jobs "$JOBS" --workdir "$WORKDIR"
case "$PROFILE" in
nested|nested-default)
	;;
*)
	set -- "$@" --prepare-host --bridge "$BRIDGE" --uplink "$UPLINK"
	;;
esac
if [ -n "${ISO:-}" ]; then
	set -- "$@" --iso "$ISO"
fi
if [ -n "${FIVEBSD_IMAGE:-}" ]; then
	set -- "$@" --fivebsd-image "$FIVEBSD_IMAGE"
fi
case "$PROFILE" in
nested|nested-default|intel-qualification|full-qualification)
	: "${NESTED_L1_RUNNER:?set NESTED_L1_RUNNER for nested qualification}"
	: "${NESTED_L1_IMAGE:?set NESTED_L1_IMAGE for nested qualification}"
	: "${NESTED_LINUX_L2_IMAGE:?set NESTED_LINUX_L2_IMAGE for nested qualification}"
	: "${NESTED_FIVEBSD_L2_IMAGE:?set NESTED_FIVEBSD_L2_IMAGE for nested qualification}"
	# The manifest gives the nested case a four-hour envelope.  Reserve its
	# final ten minutes for the mandatory VMM preflights, evidence validation,
	# sealing, and cleanup rather than allowing the external L1 runner to use
	# the whole case deadline.
	NESTED_LIVE_TIMEOUT=${NESTED_LIVE_TIMEOUT:-13800}
	NESTED_SNAPSHOT_SESSION_TIMEOUT=${NESTED_SNAPSHOT_SESSION_TIMEOUT:-120}
	case "$NESTED_LIVE_TIMEOUT" in
	''|*[!0-9]*|0)
		echo "NESTED_LIVE_TIMEOUT must be a positive integer" >&2
		exit 1
		;;
	esac
	case "$NESTED_SNAPSHOT_SESSION_TIMEOUT" in
	''|*[!0-9]*|0)
		echo "NESTED_SNAPSHOT_SESSION_TIMEOUT must be a positive integer" >&2
		exit 1
		;;
	esac
	set -- "$@" \
	    --set "NESTED_L1_RUNNER=$NESTED_L1_RUNNER" \
	    --set "NESTED_L1_IMAGE=$NESTED_L1_IMAGE" \
	    --set "NESTED_LINUX_L2_IMAGE=$NESTED_LINUX_L2_IMAGE" \
	    --set "NESTED_FIVEBSD_L2_IMAGE=$NESTED_FIVEBSD_L2_IMAGE" \
	    --set "NESTED_LIVE_TIMEOUT=$NESTED_LIVE_TIMEOUT" \
	    --set "NESTED_SNAPSHOT_SESSION_TIMEOUT=$NESTED_SNAPSHOT_SESSION_TIMEOUT"
	if [ -n "${NESTED_SNAPSHOT_SESSION_TEST:-}" ]; then
		set -- "$@" \
		    --set "NESTED_SNAPSHOT_SESSION_TEST=$NESTED_SNAPSHOT_SESSION_TEST"
	fi
	if [ -n "${NESTED_STARTUP_STAGING_TEST:-}" ]; then
		set -- "$@" \
		    --set "NESTED_STARTUP_STAGING_TEST=$NESTED_STARTUP_STAGING_TEST"
	fi
	;;
esac
case "$PROFILE" in
audio|checkpoint-audio|audio-qualification|full-qualification)
	SOUND_PLAY=${SOUND_PLAY:-/dev/dsp}
	SOUND_RECORD=${SOUND_RECORD:-/dev/dsp}
	set -- "$@" \
	    --set "SOUND_PLAY=$SOUND_PLAY" \
	    --set "SOUND_RECORD=$SOUND_RECORD"
	;;
esac
if [ "$RESUME" = yes ]; then
	set -- "$@" --resume
fi
if [ "$PLAN_ONLY" = yes ]; then
	printf '%s\n' "qualification-plan profile=$PROFILE"
	for argument do
		printf '%s\t%s\n' "argument" "$argument"
	done
	exit 0
fi
exec "$@"
