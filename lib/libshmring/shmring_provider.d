provider shmring {
	probe create(uint64_t capacity, uint32_t mode, uint32_t max_record,
	    int result);
	probe open(uint32_t role, uint64_t capacity, uint32_t mode, int result);
	probe close(uint32_t role, uint64_t capacity);
	probe write(uint32_t mode, uint64_t requested, uint64_t completed,
	    int result);
	probe read(uint32_t mode, uint64_t requested, uint64_t completed,
	    int result);
	probe corrupt(uint64_t head, uint64_t tail, uint64_t capacity);
};
