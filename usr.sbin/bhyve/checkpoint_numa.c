/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "checkpoint_numa.h"

#define	CHECKPOINT_NUMA_SIZE_WIDTH	16
#define	CHECKPOINT_NUMA_DOMAIN_WIDTH	4

static int
checkpoint_numa_text_size(size_t count, size_t width, size_t *result)
{

	if (result == NULL || count == 0)
		return (EINVAL);
	if (count > (SIZE_MAX - 1) / (width + 1))
		return (EOVERFLOW);
	*result = count * width + (count - 1) + 1;
	return (0);
}

static int
checkpoint_numa_hex_digit(char value, uint8_t *digit)
{

	if (value >= '0' && value <= '9')
		*digit = (uint8_t)(value - '0');
	else if (value >= 'a' && value <= 'f')
		*digit = (uint8_t)(value - 'a' + 10);
	else
		return (EINVAL);
	return (0);
}

static int
checkpoint_numa_hex_decode(const char *text, size_t width, uint64_t *value)
{
	uint64_t decoded;
	uint8_t digit;
	int error;

	if (text == NULL || value == NULL || width == 0 || width > 16)
		return (EINVAL);
	decoded = 0;
	for (size_t i = 0; i < width; i++) {
		error = checkpoint_numa_hex_digit(text[i], &digit);
		if (error != 0)
			return (error);
		decoded = (decoded << 4) | digit;
	}
	*value = decoded;
	return (0);
}

static int
checkpoint_numa_hex_list_count(const char *text, size_t width, size_t maximum,
    size_t *count)
{
	size_t length, stride;

	if (text == NULL || count == NULL || width == 0 || maximum == 0)
		return (EINVAL);
	length = strlen(text);
	stride = width + 1;
	if (length < width || (length + 1) % stride != 0)
		return (EINVAL);
	*count = (length + 1) / stride;
	if (*count == 0 || *count > maximum)
		return (EINVAL);
	for (size_t i = 0; i < *count; i++) {
		if (i + 1 < *count && text[i * stride + width] != ',')
			return (EINVAL);
	}
	return (0);
}

int
checkpoint_numa_encode(const uint64_t *domain_sizes, size_t domain_count,
    const uint16_t *vcpu_domains, size_t vcpu_count, char **sizes_text,
    char **mapping_text)
{
	char *mapping, *sizes;
	uint64_t memory_size;
	size_t mapping_size, sizes_size;
	int error, length;

	if (domain_sizes == NULL || domain_count == 0 ||
	    domain_count > CHECKPOINT_NUMA_MAX_DOMAINS ||
	    vcpu_domains == NULL || vcpu_count == 0 ||
	    vcpu_count > UINT16_MAX || sizes_text == NULL ||
	    mapping_text == NULL)
		return (EINVAL);
	*sizes_text = NULL;
	*mapping_text = NULL;
	memory_size = 0;
	for (size_t i = 0; i < domain_count; i++) {
		if (domain_sizes[i] == 0 ||
		    domain_sizes[i] > UINT64_MAX - memory_size)
			return (EINVAL);
		memory_size += domain_sizes[i];
	}
	error = checkpoint_numa_mapping_validate(domain_sizes, domain_count,
	    vcpu_domains, vcpu_count, memory_size);
	if (error != 0)
		return (error);

	error = checkpoint_numa_text_size(domain_count,
	    CHECKPOINT_NUMA_SIZE_WIDTH, &sizes_size);
	if (error == 0)
		error = checkpoint_numa_text_size(vcpu_count,
		    CHECKPOINT_NUMA_DOMAIN_WIDTH, &mapping_size);
	if (error != 0)
		return (error);
	sizes = malloc(sizes_size);
	mapping = malloc(mapping_size);
	if (sizes == NULL || mapping == NULL) {
		free(sizes);
		free(mapping);
		return (ENOMEM);
	}
	for (size_t i = 0; i < domain_count; i++) {
		length = snprintf(sizes + i * (CHECKPOINT_NUMA_SIZE_WIDTH + 1),
		    sizes_size - i * (CHECKPOINT_NUMA_SIZE_WIDTH + 1),
		    "%016jx%s", (uintmax_t)domain_sizes[i],
		    i + 1 == domain_count ? "" : ",");
		if (length != CHECKPOINT_NUMA_SIZE_WIDTH +
		    (i + 1 == domain_count ? 0 : 1))
			goto encoding_failure;
	}
	for (size_t i = 0; i < vcpu_count; i++) {
		length = snprintf(mapping +
		    i * (CHECKPOINT_NUMA_DOMAIN_WIDTH + 1),
		    mapping_size - i * (CHECKPOINT_NUMA_DOMAIN_WIDTH + 1),
		    "%04x%s", (unsigned int)vcpu_domains[i],
		    i + 1 == vcpu_count ? "" : ",");
		if (length != CHECKPOINT_NUMA_DOMAIN_WIDTH +
		    (i + 1 == vcpu_count ? 0 : 1))
			goto encoding_failure;
	}
	*sizes_text = sizes;
	*mapping_text = mapping;
	return (0);

encoding_failure:
	free(sizes);
	free(mapping);
	return (EIO);
}

int
checkpoint_numa_decode(const char *sizes_text, const char *mapping_text,
    size_t expected_vcpus, uint64_t expected_memory,
    uint64_t domain_sizes[CHECKPOINT_NUMA_MAX_DOMAINS],
    size_t *domain_count, uint16_t *vcpu_domains)
{
	uint16_t *staged_mapping;
	uint64_t staged_sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
	uint64_t decoded;
	size_t domains, mappings;
	int error;

	if (domain_sizes == NULL || domain_count == NULL ||
	    vcpu_domains == NULL || expected_vcpus == 0 ||
	    expected_vcpus > UINT16_MAX || expected_memory == 0)
		return (EINVAL);
	error = checkpoint_numa_hex_list_count(sizes_text,
	    CHECKPOINT_NUMA_SIZE_WIDTH, CHECKPOINT_NUMA_MAX_DOMAINS, &domains);
	if (error == 0)
		error = checkpoint_numa_hex_list_count(mapping_text,
		    CHECKPOINT_NUMA_DOMAIN_WIDTH, expected_vcpus, &mappings);
	if (error != 0 || mappings != expected_vcpus)
		return (EINVAL);

	staged_mapping = calloc(expected_vcpus, sizeof(*staged_mapping));
	if (staged_mapping == NULL)
		return (ENOMEM);
	memset(staged_sizes, 0, sizeof(staged_sizes));
	for (size_t i = 0; i < domains; i++) {
		error = checkpoint_numa_hex_decode(sizes_text +
		    i * (CHECKPOINT_NUMA_SIZE_WIDTH + 1),
		    CHECKPOINT_NUMA_SIZE_WIDTH, &staged_sizes[i]);
		if (error != 0)
			goto done;
	}
	for (size_t i = 0; i < mappings; i++) {
		error = checkpoint_numa_hex_decode(mapping_text +
		    i * (CHECKPOINT_NUMA_DOMAIN_WIDTH + 1),
		    CHECKPOINT_NUMA_DOMAIN_WIDTH, &decoded);
		if (error != 0 || decoded > UINT16_MAX) {
			error = EINVAL;
			goto done;
		}
		staged_mapping[i] = (uint16_t)decoded;
	}
	error = checkpoint_numa_mapping_validate(staged_sizes, domains,
	    staged_mapping, mappings, expected_memory);
	if (error != 0)
		goto done;
	memcpy(domain_sizes, staged_sizes, sizeof(staged_sizes));
	memcpy(vcpu_domains, staged_mapping,
	    expected_vcpus * sizeof(*vcpu_domains));
	*domain_count = domains;

done:
	free(staged_mapping);
	return (error);
}
