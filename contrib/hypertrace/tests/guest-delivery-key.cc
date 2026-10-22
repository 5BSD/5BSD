/* SPDX-License-Identifier: BSD-2-Clause */
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <openssl/sha.h>
struct guest_delivery {
    uint64_t delivery_id = 71;
    uint16_t vmid = 42;
    uint64_t epoch = 99;
    std::array<uint8_t, 16> program_id{1}, source_id{2};
    std::array<uint8_t, 16> journal_session_id{};
    uint8_t journal_version = 3;
    std::array<uint8_t, 32> payload_digest{};
};
struct durable_delivery {
    std::array<uint8_t, 16> session_id{}, program_id{}, source_id{};
    uint64_t delivery_id = 0;
    uint16_t vmid = 0;
    uint64_t epoch = 0;
    uint8_t scope = 0;
    uint8_t journal_version = 3;
    std::array<uint8_t, 32> payload_digest{};
};
#include "guest-delivery-key.inc"
int main(void) {
    guest_delivery delivery{};
    auto source = guest_delivery_record(delivery);
    assert((source.scope == 1 && source.session_id !=
        std::array<uint8_t, 16>{}));
    delivery.journal_session_id = source.session_id;
    delivery.vmid = 43;
    delivery.epoch = 100;
    auto migrated = guest_delivery_record(delivery);
    assert(migrated.session_id == source.session_id &&
        migrated.vmid == 43 && migrated.epoch == 100);
    delivery.journal_session_id.fill(0);
    delivery.journal_version = 4;
    delivery.payload_digest[0] = 9;
    auto fresh = guest_delivery_record(delivery);
    assert(fresh.session_id != source.session_id &&
        fresh.vmid == migrated.vmid && fresh.journal_version == 4 &&
        fresh.payload_digest[0] == 9);
    puts("PASS: migrated inbound journal keeps its durable session key");
}
