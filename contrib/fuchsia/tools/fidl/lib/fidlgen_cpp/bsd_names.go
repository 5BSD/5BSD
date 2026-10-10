// SPDX-License-Identifier: BSD-2-Clause
// Copyright 2026 The 5BSD Authors.
// 5BSD addition to the Fuchsia import; not covered by Fuchsia's PATENTS.

package fidlgen_cpp

import "go.fuchsia.dev/fuchsia/tools/fidl/lib/fidlgen"

// BSDNames exports the same transformations used by the natural-type templates.
// Native protocol/C projections must not guess C++ spelling from FIDL names.
func BSDNames(r fidlgen.Root) map[string]map[string]string {
	c := compiler{decls: r.DeclInfo(), library: r.Name.Parse()}
	types := map[string]string{}
	members := map[string]string{}
	for id, info := range c.decls {
		switch info.Type {
		case fidlgen.AliasDeclType, fidlgen.BitsDeclType, fidlgen.ConstDeclType,
			fidlgen.EnumDeclType, fidlgen.ProtocolDeclType, fidlgen.StructDeclType,
			fidlgen.TableDeclType, fidlgen.UnionDeclType:
			types[string(id)] = c.compileNameVariants(id).Unified.String()
		}
	}
	for _, d := range r.Structs {
		for _, m := range d.Members {
			members[string(d.Name)+"/"+string(m.Name)] = structMemberContext.transform(m.Name).Unified.String()
		}
	}
	for _, d := range r.Tables {
		for _, m := range d.Members {
			members[string(d.Name)+"/"+string(m.Name)] = tableMemberContext.transform(m.Name).Unified.String()
		}
	}
	for _, d := range r.Unions {
		for _, m := range d.Members {
			members[string(d.Name)+"/"+string(m.Name)] = unionMemberContext.transform(m.Name).Unified.String()
		}
	}
	for _, d := range r.Protocols {
		for _, m := range d.Methods {
			members[string(d.Name)+"/"+string(m.Name)] = methodNameContext.transform(m.Name).Unified.String()
		}
	}
	return map[string]map[string]string{"types": types, "members": members}
}
