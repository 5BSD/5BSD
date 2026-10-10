/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef FIDL_BSD_EMPTY_H
#define FIDL_BSD_EMPTY_H
namespace fidl::bsd {
// A payload-free transaction has only its header, unlike an empty FIDL struct.
// It bypasses the standalone domain-object codec, which requires a body.
struct Empty { };
}
#endif
