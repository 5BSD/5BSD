#!/bin/sh
#
# Common host-side live evidence for indirect descriptor consumption and
# EVENT_IDX decisions.  Source this file from a root-only VM harness.

virtio_ring_trace_pid=

virtio_ring_trace_start()
{
	target_pid=$1
	trace_file=$2

	command -v dtrace >/dev/null 2>&1 || {
		echo "virtio ring tracing requires dtrace" >&2
		return 1
	}
	dtrace -l -p "$target_pid" \
	    -n 'virtio$target:::transport-descriptor-chain' 2>/dev/null |
	    grep -q 'transport-descriptor-chain' || {
		echo "virtio descriptor-chain USDT probe is unavailable" >&2
		return 1
	}
	dtrace -Z -q -p "$target_pid" -o "$trace_file" \
	    -n 'virtio$target:::transport-descriptor-chain {
		printf("chain %s %u %u %u %u\n", copyinstr(arg0),
		    arg1, arg2, arg3, arg4);
	    }' \
	    -n 'virtio$target:::transport-event-idx {
		printf("event %s %u split %u %u %u\n", copyinstr(arg0),
		    arg1, arg2, arg3, arg4);
	    }' \
	    -n 'virtio$target:::transport-packed-event-idx {
		printf("event %s %u packed %u %u %u\n", copyinstr(arg0),
		    arg1, arg2, arg3, arg4);
	    }' \
	    -n 'virtio$target:::iommu-translate {
		printf("iommu %s %u %llu %llu %u\n", copyinstr(arg0),
		    arg1, arg2, arg3, arg4);
	    }' \
	    -n 'virtio$target:::gpu-command {
		printf("gpu %s %u %u %u %u\n", copyinstr(arg0),
		    arg1, arg2, arg3, arg4);
	    }' \
	    -n 'virtio$target:::net-rx-hash {
		printf("nethash %s %u %u %u %u\n", copyinstr(arg0),
		    arg1, arg2, arg3, arg4);
	    }' &
	virtio_ring_trace_pid=$!
	sleep 1
	kill -0 "$virtio_ring_trace_pid" 2>/dev/null || {
		echo "virtio ring DTrace consumer exited during startup" >&2
		virtio_ring_trace_pid=
		return 1
	}
}

virtio_ring_trace_stop()
{
	if [ -n "$virtio_ring_trace_pid" ]; then
		kill -INT "$virtio_ring_trace_pid" 2>/dev/null || true
		wait "$virtio_ring_trace_pid" 2>/dev/null || true
	fi
	virtio_ring_trace_pid=
}

virtio_ring_trace_finish()
{
	trace_file=$1
	layout=${2:-split}
	device=${3:-}

	virtio_ring_trace_stop
	awk -v device="$device" \
	    '$1 == "chain" && (device == "" || $2 == device) &&
	    $5 == 1 && $6 > 0 { found = 1 }
	    END { exit found ? 0 : 1 }' "$trace_file" || {
		echo "FAIL  host_indirect_descriptor_data device=${device:-any}" >&2
		return 1
	}
	awk -v layout="$layout" -v device="$device" \
	    '$1 == "event" && (device == "" || $2 == device) &&
	    $4 == layout && $7 == 0 { found = 1 }
	    END { exit found ? 0 : 1 }' "$trace_file" || {
		echo "FAIL  host_event_idx_suppression device=${device:-any} layout=$layout" >&2
		return 1
	}
	awk -v layout="$layout" -v device="$device" \
	    '$1 == "event" && (device == "" || $2 == device) &&
	    $4 == layout && $7 == 1 { found = 1 }
	    END { exit found ? 0 : 1 }' "$trace_file" || {
		echo "FAIL  host_event_idx_interrupt device=${device:-any} layout=$layout" >&2
		return 1
	}
	echo "PASS  host_indirect_descriptor_data device=${device:-any}"
	echo "PASS  host_event_idx device=${device:-any} layout=$layout suppression=yes interrupt=yes"
}

virtio_net_hash_trace_finish()
{
	trace_file=$1
	expected_pairs=$2

	case "$expected_pairs" in
	''|*[!0-9]*|0)
		echo "invalid expected network queue-pair count: $expected_pairs" >&2
		return 2
		;;
	esac
	# VirtIO 1.4 section 5.1.6.5.5 assigns receive queues the even
	# virtqueue indices.  Section 5.1.6.5.7.4 assigns nonzero report
	# values 1 through 6 to IPv4/IPv6 and TCP/UDP packet classes.
	awk -v pairs="$expected_pairs" \
	    '$1 == "nethash" && $2 == "vtnet" && ($3 % 2) == 0 &&
	    ($3 / 2) < pairs && $5 >= 1 && $5 <= 6 && $6 > 0 {
		found = 1
	    }
	    END { exit found ? 0 : 1 }' "$trace_file" || {
		echo "FAIL  host_net_hash_report pairs=$expected_pairs" >&2
		return 1
	}
	echo "PASS  host_net_hash_report pairs=$expected_pairs metadata=yes"
}

virtio_gpu_blob_trace_require()
{
	target_pid=$1

	dtrace -l -p "$target_pid" \
	    -n 'virtio$target:::gpu-command' 2>/dev/null |
	    grep -q 'gpu-command' || {
		echo "virtio GPU command USDT probe is unavailable" >&2
		return 1
	}
}

virtio_gpu_blob_trace_finish()
{
	trace_file=$1

	# VirtIO 1.4 section 5.7.6 command values, deliberately independent
	# of the device-model headers under test.
	for command in 268 269; do
		awk -v command="$command" \
		    '$1 == "gpu" && $2 == "vtgpu" && $4 == command &&
		    $5 > 0 && $6 == 0 { found = 1 }
		    END { exit found ? 0 : 1 }' "$trace_file" || {
			echo "FAIL  host_gpu_blob_command command=$command" >&2
			return 1
		}
	done
	echo "PASS  host_gpu_blob_commands create=yes set_scanout=yes"
}

virtio_device_ring_trace_finish()
{
	trace_file=$1
	layout=$2
	device=$3

	case "$layout" in
	split) packed=0 ;;
	packed) packed=1 ;;
	*)
		echo "invalid ring layout: $layout" >&2
		return 2
		;;
	esac
	case "$device" in
	''|*[!A-Za-z0-9_-]*)
		echo "invalid VirtIO trace device name: $device" >&2
		return 2
		;;
	esac
	awk -v device="$device" -v packed="$packed" \
	    '$1 == "chain" && $2 == device && $4 == packed && $6 > 0 {
		found = 1
	    }
	    END { exit found ? 0 : 1 }' "$trace_file" || {
		echo "FAIL  host_device_ring device=$device layout=$layout" >&2
		return 1
	}
	echo "PASS  host_device_ring device=$device layout=$layout"
}

virtio_iommu_trace_finish()
{
	trace_file=$1
	expected_endpoints=$2

	case "$expected_endpoints" in
	''|*[!0-9]*|0)
		echo "invalid expected IOMMU endpoint count: $expected_endpoints" >&2
		return 2
		;;
	esac
	awk '$1 == "iommu" && $6 == 0 { failed = 1 }
	    END { exit failed ? 0 : 1 }' "$trace_file" && {
		echo "FAIL  host_iommu_translation observed a rejected DMA translation" >&2
		return 1
	}
	observed=$(awk '$1 == "iommu" && $6 == 1 { endpoint[$3] = 1 }
	    END { for (value in endpoint) count++; print count + 0 }' \
	    "$trace_file")
	[ "$observed" -eq "$expected_endpoints" ] || {
		echo "FAIL  host_iommu_translation endpoints=$observed expected=$expected_endpoints" >&2
		return 1
	}
	echo "PASS  host_iommu_translation endpoints=$observed failures=0"
}
