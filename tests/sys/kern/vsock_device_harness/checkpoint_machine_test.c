#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "checkpoint_machine.c"

static void
make_compat(struct pci_snapshot_compat *compat, uint32_t transport,
    const char *queues, const char *shared)
{

	memset(compat, 0, sizeof(*compat));
	compat->schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
	compat->transport = transport;
	compat->queue_count = 2;
	compat->msix_table_count = 3;
	compat->config_size = 64;
	compat->offered_features = UINT64_C(0x8000000100000000);
	compat->negotiated_features = UINT64_C(0x100000000);
	compat->payload_crc32 = UINT32_C(0x12345678);
	strlcpy(compat->queue_sizes, queues, sizeof(compat->queue_sizes));
	strlcpy(compat->shared_memory, shared, sizeof(compat->shared_memory));
}

ATF_TC_WITHOUT_HEAD(canonical_and_order_independent);
ATF_TC_BODY(canonical_and_order_independent, tc)
{
	struct pci_snapshot_compat net;
	struct checkpoint_machine_device forward[3], reverse[3];
	char a[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	char b[CHECKPOINT_MACHINE_DIGEST_LENGTH];

	make_compat(&net, 1, "256,256", "1:4:4096:8192");
	forward[0] = (struct checkpoint_machine_device){ "virtio-net@pci.0.4.0", &net };
	forward[1] = (struct checkpoint_machine_device){ "ahci@pci.0.3.0", NULL };
	forward[2] = (struct checkpoint_machine_device){ "atkbdc", NULL };
	reverse[0] = forward[2];
	reverse[1] = forward[1];
	reverse[2] = forward[0];
	ATF_REQUIRE_EQ(checkpoint_machine_topology_digest(forward, 3, a,
	    sizeof(a)), 0);
	ATF_REQUIRE_EQ(checkpoint_machine_topology_digest(reverse, 3, b,
	    sizeof(b)), 0);
	ATF_CHECK_STREQ(a, b);
	ATF_CHECK(checkpoint_machine_digest_canonical(a));
	ATF_CHECK(!checkpoint_machine_digest_canonical("ABC"));
	a[0] = 'A';
	ATF_CHECK(!checkpoint_machine_digest_canonical(a));
}

ATF_TC_WITHOUT_HEAD(topology_fields_are_sealed);
ATF_TC_BODY(topology_fields_are_sealed, tc)
{
	struct pci_snapshot_compat source, changed;
	struct checkpoint_machine_device device;
	char baseline[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	char digest[CHECKPOINT_MACHINE_DIGEST_LENGTH];

	make_compat(&source, 1, "256,256", "1:4:4096:8192");
	device = (struct checkpoint_machine_device){ "virtio-net@pci.0.4.0", &source };
	ATF_REQUIRE_EQ(checkpoint_machine_topology_digest(&device, 1, baseline,
	    sizeof(baseline)), 0);

#define CHECK_CHANGED(statement) do { \
	changed = source; \
	statement; \
	device.compat = &changed; \
	ATF_REQUIRE_EQ(checkpoint_machine_topology_digest(&device, 1, digest, \
	    sizeof(digest)), 0); \
	ATF_CHECK(strcmp(baseline, digest) != 0); \
} while (0)
	CHECK_CHANGED(changed.transport++);
	CHECK_CHANGED(changed.queue_count++);
	CHECK_CHANGED(changed.msix_table_count++);
	CHECK_CHANGED(changed.config_size++);
	CHECK_CHANGED(strlcpy(changed.queue_sizes, "128,256",
	    sizeof(changed.queue_sizes)));
	CHECK_CHANGED(strlcpy(changed.shared_memory, "1:4:4096:4096",
	    sizeof(changed.shared_memory)));
#undef CHECK_CHANGED

	/* Feature negotiation and payload integrity have separate contracts. */
	changed = source;
	changed.offered_features ^= 1;
	changed.negotiated_features ^= 1;
	changed.payload_crc32 ^= 1;
	device.compat = &changed;
	ATF_REQUIRE_EQ(checkpoint_machine_topology_digest(&device, 1, digest,
	    sizeof(digest)), 0);
	ATF_CHECK_STREQ(baseline, digest);
}

ATF_TC_WITHOUT_HEAD(rejects_ambiguous_or_invalid_input);
ATF_TC_BODY(rejects_ambiguous_or_invalid_input, tc)
{
	struct pci_snapshot_compat compat;
	struct checkpoint_machine_device devices[2];
	char digest[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	char before[CHECKPOINT_MACHINE_DIGEST_LENGTH];

	make_compat(&compat, 1, "256,256", "1:4:4096:8192");
	devices[0] = (struct checkpoint_machine_device){ "same", &compat };
	devices[1] = (struct checkpoint_machine_device){ "same", NULL };
	memset(digest, 0xa5, sizeof(digest));
	memcpy(before, digest, sizeof(before));
	ATF_CHECK_EQ(checkpoint_machine_topology_digest(devices, 2, digest,
	    sizeof(digest)), EEXIST);
	ATF_CHECK_EQ(memcmp(digest, before, sizeof(digest)), 0);
	devices[1].name = "other";
	memset(compat.queue_sizes, 'x', sizeof(compat.queue_sizes));
	ATF_CHECK_EQ(checkpoint_machine_topology_digest(devices, 2, digest,
	    sizeof(digest)), EINVAL);
	ATF_CHECK_EQ(checkpoint_machine_topology_digest(NULL, 1, digest,
	    sizeof(digest)), EINVAL);
	ATF_CHECK_EQ(checkpoint_machine_topology_digest(devices, 2, digest,
	    sizeof(digest) - 1), EINVAL);
}

/*
 * A machine with no PCI or architecture-owned legacy devices is unusual, but
 * it is a valid input to the common seal routine.  Keep that base case
 * deterministic and independent of calloc(0)'s implementation-defined return
 * value: callers use it when assembling a topology before optional devices
 * have been registered.
 */
ATF_TC_WITHOUT_HEAD(empty_topology_is_canonical);
ATF_TC_BODY(empty_topology_is_canonical, tc)
{
	char first[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	char second[CHECKPOINT_MACHINE_DIGEST_LENGTH];

	ATF_REQUIRE_EQ(checkpoint_machine_topology_digest(NULL, 0, first,
	    sizeof(first)), 0);
	ATF_REQUIRE_EQ(checkpoint_machine_topology_digest(NULL, 0, second,
	    sizeof(second)), 0);
	ATF_CHECK_STREQ(first, second);
	ATF_CHECK(checkpoint_machine_digest_canonical(first));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, canonical_and_order_independent);
	ATF_TP_ADD_TC(tp, topology_fields_are_sealed);
	ATF_TP_ADD_TC(tp, rejects_ambiguous_or_invalid_input);
	ATF_TP_ADD_TC(tp, empty_topology_is_canonical);
	return (atf_no_error());
}
