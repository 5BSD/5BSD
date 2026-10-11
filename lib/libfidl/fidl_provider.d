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
	probe validation__failed(uintptr_t message, uint32_t txid, uint64_t ordinal,
	    int reason);
	probe message__token(uintptr_t connection, uint32_t txid, uint64_t ordinal,
	    uint64_t token);
	probe epitaph(uintptr_t connection, int status);
	probe reject(uintptr_t connection, uint32_t txid, uint64_t ordinal,
	    int reason);
	probe transport(uintptr_t connection, uintptr_t channel, uint32_t txid,
	    uint64_t ordinal);
};
