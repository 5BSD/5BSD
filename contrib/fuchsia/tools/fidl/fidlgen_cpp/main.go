// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"go.fuchsia.dev/fuchsia/tools/fidl/fidlgen_cpp/codegen"
	cpp "go.fuchsia.dev/fuchsia/tools/fidl/lib/fidlgen_cpp"
	"log"
	"os"
)

func main() {
	flags := cpp.NewCmdlineFlags("llcpp", []string{"api_coverage"})
	flag.BoolVar(&flags.NativeBSD, "native-bsd", false, "generate native BSD natural types only")
	namesPath := flag.String("bsd-names", "", "write native binding name metadata")
	ir := flags.ParseAndLoadIR()
	root := cpp.Compile(ir)
	if flags.NativeBSD {
		root = cpp.CompileBSD(ir)
	}
	generator := codegen.NewGenerator(flags)
	if flags.NativeBSD {
		if *namesPath != "" {
			data, err := json.MarshalIndent(cpp.BSDNames(ir), "", "  ")
			if err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(*namesPath, append(data, '\n'), 0644); err != nil {
				log.Fatal(err)
			}
		}
		generator.GenerateFiles(root, []string{"Markers", "CommonTypesHeader", "CommonTypesSource", "NaturalTypesHeader", "NaturalTypesSource"})
		return
	}
	generator.GenerateFiles(root, []string{
		"WireHeader", "UnifiedHeader", "WireTestBase", "TestBase", "Markers",
		"CommonTypesHeader", "CommonTypesSource",
		"CommonTypesFormatHeader",
		"WireTypesHeader", "WireTypesSource",
		"WireMessagingHeader", "WireMessagingSource",
		"NaturalTypesHeader", "NaturalOStreamSource",
		"NaturalOStreamHeader", "NaturalTypesSource",
		"NaturalMessagingHeader", "NaturalMessagingSource",
		"TypeConversionsHeader", "TypeConversionsSource",
		"HLCPPConversion",
		"driver/WireHeader", "driver/WireTestBase",
		"driver/WireMessagingHeader", "driver/WireMessagingSource",
		"driver/NaturalMessagingHeader", "driver/NaturalMessagingSource",
		"driver/UnifiedHeader", "driver/TestBase",
	})
}
