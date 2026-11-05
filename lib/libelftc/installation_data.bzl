# SPDX-License-Identifier: BSD-2-Clause
# Original lib/libelftc/Makefile MAN and MLINKS; INTERNALLIB installs no headers.
MANUALS = [
    "elftc.3",
    "elftc_bfd_find_target.3",
    "elftc_copyfile.3",
    "elftc_demangle.3",
    "elftc_reloc_type_str.3",
    "elftc_set_timestamps.3",
    "elftc_timestamp.3",
    "elftc_string_table_create.3",
    "elftc_version.3",
]
MANUAL_LINKS = [
    ("elftc_bfd_find_target.3", "elftc_bfd_target_class.3"),
    ("elftc_bfd_find_target.3", "elftc_bfd_target_byteorder.3"),
    ("elftc_bfd_find_target.3", "elftc_bfd_target_flavor.3"),
    ("elftc_bfd_find_target.3", "elftc_bfd_target_machine.3"),
    ("elftc_string_table_create.3", "elftc_string_table_destroy.3"),
    ("elftc_string_table_create.3", "elftc_string_table_from_section.3"),
    ("elftc_string_table_create.3", "elftc_string_table_image.3"),
    ("elftc_string_table_create.3", "elftc_string_table_insert.3"),
    ("elftc_string_table_create.3", "elftc_string_table_lookup.3"),
    ("elftc_string_table_create.3", "elftc_string_table_remove.3"),
    ("elftc_string_table_create.3", "elftc_string_table_to_string.3"),
]
