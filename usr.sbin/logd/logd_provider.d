provider logd {
	probe pool__start(uint32_t shard, uint32_t capacity, int result);
	probe pool__admit(uint32_t shard, const char *label, uint32_t active,
	    int result);
	probe pool__shutdown(uint32_t shard, uint32_t active, int result);
	probe session__start(const char *label, uint64_t instance, int result);
	probe session__end(const char *label, uint64_t instance, int result);
	probe record__write(const char *label, uint32_t severity, uint32_t length,
	    int result);
	probe record__drop(const char *label, uint64_t sequence, int error);
	probe wakeup__receive(const char *label, uint64_t instance, int result);
	probe batch__drain(const char *label, uint64_t instance,
	    const char *reason, uint64_t records, int result);
	probe flush__complete(const char *label, uint64_t instance,
	    uint64_t records, uint64_t duration_ns, int result);
	probe storage__persist(const char *label, uint64_t generation,
	    uint64_t offset, uint32_t length, int result);
	probe storage__rotate(uint64_t generation, int result);
	probe storage__corruption(uint64_t generation, uint64_t offset,
	    int error);
	probe storage__quarantine(uint64_t generation, int error);
	probe query__complete(const char *label, uint64_t generation,
	    uint64_t offset, uint32_t minimum_severity, uint32_t record_length,
	    int result);
	probe query__filter(const char *label, uint64_t scanned,
	    uint64_t matched, int result);
	probe retention__prune(uint64_t generation, uint64_t records,
	    uint64_t bytes, int reason);
};
