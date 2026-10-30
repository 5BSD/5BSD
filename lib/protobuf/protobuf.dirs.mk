# SPDX-License-Identifier: BSD-2-Clause
#
# Where protoc and its upb plugins are installed: in the target, and under
# ${WORLDTMP}/legacy for the bootstrap copies that lib/protobuf/protoc-gen.mk
# runs.  protoc is not on the default PATH: the C++ runtime it generates code
# for is private to the base system, and a /usr/bin/protoc would shadow the
# ports protoc (and satisfy ports' BUILD_DEPENDS on it).  Base components
# call it by its full path, through protoc-gen.mk.  Moving it is this line,
# plus the paths in usr.bin/protoc/protoc.1 and the documentation.

PROTOC_BINDIR?=		/usr/libexec
PROTOC_PLUGINDIR?=	/usr/libexec
