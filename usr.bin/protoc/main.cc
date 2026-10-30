// SPDX-License-Identifier: BSD-3-Clause
//
// protoc for the 5BSD base system: upstream's driver
// (contrib/protobuf/src/google/protobuf/compiler/main.cc) with only the
// C++ generator registered, because the other language generators are not
// imported (contrib/protobuf/README.5BSD).  Plugins (protoc-gen-NAME on
// PATH, or --plugin=) work as upstream; the upb C generators are installed
// as /usr/libexec/protoc-gen-upb and /usr/libexec/protoc-gen-upb_minitable.
//
// Derived from upstream main.cc:
// Copyright 2008 Google Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in /usr/share/licenses/protobuf/LICENSE.

#include "absl/log/initialize.h"
#include "google/protobuf/compiler/command_line_interface.h"
#include "google/protobuf/compiler/cpp/generator.h"

int
main(int argc, char *argv[])
{
	absl::InitializeLog();

	google::protobuf::compiler::CommandLineInterface cli;
	cli.AllowPlugins("protoc-");

	google::protobuf::compiler::cpp::CppGenerator cpp_generator;
	cli.RegisterGenerator("--cpp_out", "--cpp_opt", &cpp_generator,
	    "Generate C++ header and source.");

	return (cli.Run(argc, argv));
}
