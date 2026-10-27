/* SPDX-License-Identifier: BSD-2-Clause */
#include <cbor.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(void)
{
	/* {"a": [1,2,3], "b": true}, [24,true], and a binary string. */
	static const unsigned char map[] = {0xa2,0x61,0x61,0x83,1,2,3,0x61,0x62,0xf5};
	static const unsigned char array[] = {0x82,0x18,0x18,0xf5};
	static const unsigned char bytes[] = {0x44,0,0xff,0x80,0x7f};
	static const unsigned char invalid[] = {0xff,0x1c,0x1d,0x1e};
	static const struct {
		const unsigned char *data;
		size_t size;
	} vectors[] = {{map,sizeof(map)}, {array,sizeof(array)}, {bytes,sizeof(bytes)}};
	struct cbor_load_result result;
	cbor_item_t *item;
	unsigned char *encoded;
	size_t i, cut, capacity, size;

	for (i = 0; i < sizeof(vectors)/sizeof(vectors[0]); i++) {
		item = cbor_load(vectors[i].data, vectors[i].size, &result);
		if (item == NULL || result.error.code != CBOR_ERR_NONE ||
		    result.read != vectors[i].size)
			return (1);
		encoded = NULL;
		size = cbor_serialize_alloc(item, &encoded, &capacity);
		if (size != vectors[i].size || encoded == NULL || capacity < size ||
		    memcmp(encoded, vectors[i].data, size) != 0)
			return (2);
		free(encoded);
		cbor_decref(&item);
		for (cut = 0; cut < vectors[i].size; cut++) {
			item = cbor_load(vectors[i].data, cut, &result);
			if (item != NULL || result.error.code == CBOR_ERR_NONE)
				return (3);
		}
		printf("vector %zu: round trip and %zu truncations passed\n", i, cut);
	}
	for (i = 0; i < sizeof(invalid); i++) {
		item = cbor_load(&invalid[i], 1, &result);
		if (item != NULL || result.error.code == CBOR_ERR_NONE)
			return (4);
	}
	printf("four malformed encodings rejected\n");
	return (0);
}
