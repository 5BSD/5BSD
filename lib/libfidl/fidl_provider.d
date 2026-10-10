/* SPDX-License-Identifier: BSD-2-Clause */
provider fidl_bsd {
	probe request__start(uintptr_t connection, uint32_t txid, uint64_t ordinal,
	    uint64_t bytes, uint64_t descriptors);
	probe request__done(uintptr_t connection, uint32_t txid, uint64_t ordinal,
	    int error);
	probe dispatch__start(uintptr_t connection);
	probe dispatch__done(uintptr_t connection, int error);
	probe message(uintptr_t connection, uint32_t txid, uint64_t ordinal);
	probe close(uintptr_t connection, int error);
};
