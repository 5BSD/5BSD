provider crypto {
	probe named__list(const char *owner, uint32_t count, int result);
	probe reclaim(const char *owner, uint32_t reclaimed);
};
