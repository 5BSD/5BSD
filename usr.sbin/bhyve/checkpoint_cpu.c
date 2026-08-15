/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "checkpoint_cpu.h"

#define	CPU_CONTRACT_MAGIC	0x31555043U	/* "CPU1", little endian. */
#define	CPU_CONTRACT_HEADER_SIZE	16U
#define	CPU_CONTRACT_RECORD_SIZE	24U
#define	CPU_CONTRACT_MAX_BYTE_COUNT	(CPU_CONTRACT_HEADER_SIZE + \
	CHECKPOINT_CPU_MAX_RECORDS * CPU_CONTRACT_RECORD_SIZE)
#define	CPU_CONTRACT_MAX_TEXT_LENGTH	(CPU_CONTRACT_MAX_BYTE_COUNT * 2U)

static int
hex_digit(unsigned char value)
{

	return (value < 10 ? '0' + value : 'a' + value - 10);
}

static int
hex_value(char value)
{

	if (value >= '0' && value <= '9')
		return (value - '0');
	if (value >= 'a' && value <= 'f')
		return (value - 'a' + 10);
	return (-1);
}

int
checkpoint_cpu_contract_validate(const struct checkpoint_cpu_contract *contract)
{
	const struct checkpoint_cpu_record *current, *previous;

	if (contract == NULL ||
	    contract->version != CHECKPOINT_CPU_CONTRACT_VERSION ||
	    contract->record_count == 0 ||
	    contract->record_count > CHECKPOINT_CPU_MAX_RECORDS)
		return (EINVAL);
	/*
	 * This is a versioned cross-host checkpoint record.  Treat architecture as
	 * a closed wire enum rather than merely a nonzero discriminator: a future
	 * architecture needs an explicit capture and compatibility policy, not a
	 * decoder which accepts an image that no current host can interpret.
	 */
	switch (contract->architecture) {
	case CHECKPOINT_CPU_ARCH_AMD64:
	case CHECKPOINT_CPU_ARCH_ARM64:
	case CHECKPOINT_CPU_ARCH_RISCV64:
		break;
	default:
		return (EINVAL);
	}
	for (size_t i = 1; i < contract->record_count; i++) {
		previous = &contract->records[i - 1];
		current = &contract->records[i];
		if (current->selector < previous->selector ||
		    (current->selector == previous->selector &&
		    current->parameter <= previous->parameter))
			return (EINVAL);
	}
	return (0);
}

int
checkpoint_cpu_contract_match(const struct checkpoint_cpu_contract *source,
    const struct checkpoint_cpu_contract *destination)
{
	int error;

	error = checkpoint_cpu_contract_validate(source);
	if (error == 0)
		error = checkpoint_cpu_contract_validate(destination);
	if (error != 0)
		return (error);
	if (source->version != destination->version ||
	    source->architecture != destination->architecture ||
	    source->record_count != destination->record_count)
		return (EXDEV);
	for (size_t i = 0; i < source->record_count; i++) {
		if (source->records[i].selector !=
		    destination->records[i].selector ||
		    source->records[i].parameter !=
		    destination->records[i].parameter ||
		    memcmp(source->records[i].values,
		    destination->records[i].values,
		    sizeof(source->records[i].values)) != 0)
			return (EXDEV);
	}
	return (0);
}

int
checkpoint_cpu_contract_encode(const struct checkpoint_cpu_contract *contract,
    char **textp)
{
	unsigned char *bytes;
	char *text;
	size_t byte_count;
	int error;

	if (textp == NULL)
		return (EINVAL);
	*textp = NULL;
	error = checkpoint_cpu_contract_validate(contract);
	if (error != 0)
		return (error);
	if (contract->record_count >
	    (SIZE_MAX - CPU_CONTRACT_HEADER_SIZE) / CPU_CONTRACT_RECORD_SIZE)
		return (EOVERFLOW);
	byte_count = CPU_CONTRACT_HEADER_SIZE +
	    contract->record_count * CPU_CONTRACT_RECORD_SIZE;
	if (byte_count > (SIZE_MAX - 1) / 2)
		return (EOVERFLOW);
	bytes = calloc(1, byte_count);
	text = malloc(byte_count * 2 + 1);
	if (bytes == NULL || text == NULL) {
		free(bytes);
		free(text);
		return (ENOMEM);
	}
	le32enc(bytes, CPU_CONTRACT_MAGIC);
	le32enc(bytes + 4, contract->version);
	le32enc(bytes + 8, contract->architecture);
	le32enc(bytes + 12, (uint32_t)contract->record_count);
	for (size_t i = 0; i < contract->record_count; i++) {
		unsigned char *record;

		record = bytes + CPU_CONTRACT_HEADER_SIZE +
		    i * CPU_CONTRACT_RECORD_SIZE;
		le32enc(record, contract->records[i].selector);
		le32enc(record + 4, contract->records[i].parameter);
		for (size_t value = 0; value < 4; value++)
			le32enc(record + 8 + value * 4,
			    contract->records[i].values[value]);
	}
	for (size_t i = 0; i < byte_count; i++) {
		text[i * 2] = hex_digit(bytes[i] >> 4);
		text[i * 2 + 1] = hex_digit(bytes[i] & 0xf);
	}
	text[byte_count * 2] = '\0';
	free(bytes);
	*textp = text;
	return (0);
}

int
checkpoint_cpu_contract_decode(const char *text,
    struct checkpoint_cpu_contract *contract)
{
	struct checkpoint_cpu_contract candidate;
	unsigned char *bytes;
	size_t byte_count, length, record_count;
	int high, low, error;

	if (text == NULL || contract == NULL)
		return (EINVAL);
	/*
	 * This is a bounded external checkpoint field, not a C string whose
	 * length may be trusted.  Keep the limit tied to the independently
	 * specified binary record maximum before doing any allocation or decode.
	 */
	length = strnlen(text, CPU_CONTRACT_MAX_TEXT_LENGTH + 1);
	if (length > CPU_CONTRACT_MAX_TEXT_LENGTH)
		return (E2BIG);
	if ((length & 1) != 0 || length < CPU_CONTRACT_HEADER_SIZE * 2)
		return (EINVAL);
	byte_count = length / 2;
	if (byte_count < CPU_CONTRACT_HEADER_SIZE)
		return (EINVAL);
	if (byte_count > CPU_CONTRACT_MAX_BYTE_COUNT)
		return (E2BIG);
	bytes = malloc(byte_count);
	if (bytes == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < byte_count; i++) {
		high = hex_value(text[i * 2]);
		low = hex_value(text[i * 2 + 1]);
		if (high < 0 || low < 0) {
			free(bytes);
			return (EINVAL);
		}
		bytes[i] = (unsigned char)((high << 4) | low);
	}
	if (le32dec(bytes) != CPU_CONTRACT_MAGIC) {
		free(bytes);
		return (EINVAL);
	}
	record_count = le32dec(bytes + 12);
	if (record_count == 0 || record_count > CHECKPOINT_CPU_MAX_RECORDS ||
	    byte_count != CPU_CONTRACT_HEADER_SIZE +
	    record_count * CPU_CONTRACT_RECORD_SIZE) {
		free(bytes);
		return (EINVAL);
	}
	memset(&candidate, 0, sizeof(candidate));
	candidate.version = le32dec(bytes + 4);
	candidate.architecture = le32dec(bytes + 8);
	candidate.record_count = record_count;
	for (size_t i = 0; i < record_count; i++) {
		const unsigned char *record;

		record = bytes + CPU_CONTRACT_HEADER_SIZE +
		    i * CPU_CONTRACT_RECORD_SIZE;
		candidate.records[i].selector = le32dec(record);
		candidate.records[i].parameter = le32dec(record + 4);
		for (size_t value = 0; value < 4; value++)
			candidate.records[i].values[value] =
			    le32dec(record + 8 + value * 4);
	}
	free(bytes);
	error = checkpoint_cpu_contract_validate(&candidate);
	if (error != 0)
		return (error);
	*contract = candidate;
	return (0);
}
