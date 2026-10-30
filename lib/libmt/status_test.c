/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/sbuf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <bsdxml.h>
#include <mtlib.h>

int
main(void)
{
	char xml[] = "<status type=\"node\"><count type=\"uint\" size=\"8\">42</count>"
	    "<offset type=\"int\">-7</offset><label type=\"str\">Tape &amp; test</label></status>";
	struct mt_status_data data;
	struct mt_status_entry *count, *offset, *label;
	int failed;

	if (mt_get_status(xml, &data) != XML_STATUS_OK || data.error != 0)
		return (1);
	count = mt_status_entry_find(&data, "count");
	offset = mt_status_entry_find(&data, "offset");
	label = mt_status_entry_find(&data, "label");
	failed = count == NULL || offset == NULL || label == NULL;
	if (!failed)
		failed = count->var_type != MT_TYPE_UINT || count->value_unsigned != 42 ||
		    count->size != 8 || offset->var_type != MT_TYPE_INT ||
		    offset->value_signed != -7 || label->var_type != MT_TYPE_STRING ||
		    strcmp(label->value, "Tape & test") != 0 || count->parent == NULL ||
		    strcmp(count->parent->entry_name, "status") != 0;
	failed |= mt_status_entry_find(&data, "missing") != NULL;
	mt_status_free(&data);
	if (failed)
		fprintf(stderr, "libmt status tree did not preserve typed values or hierarchy\n");
	return (failed);
}
