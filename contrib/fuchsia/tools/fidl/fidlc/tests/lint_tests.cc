// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "tools/fidl/fidlc/src/diagnostics.h"
#include "tools/fidl/fidlc/tests/test_library.h"

namespace fidlc {
namespace {

using ::testing::HasSubstr;

#define ASSERT_WARNINGS(quantity, lib, content)                           \
  do {                                                                    \
    const auto& warnings = (lib).lints();                                 \
    std::string error = "Found warning: ";                                \
    for (size_t i = 0; i < warnings.size(); i++) {                        \
      error.append(warnings[i]);                                          \
    }                                                                     \
    if (strlen(content) != 0) {                                           \
      bool contains_content = false;                                      \
      for (size_t i = 0; i < warnings.size(); i++) {                      \
        if (warnings[i].find(content) != std::string::npos) {             \
          contains_content = true;                                        \
          break;                                                          \
        }                                                                 \
      }                                                                   \
      ASSERT_TRUE(contains_content) << (content) << "\n" << error;        \
    }                                                                     \
    if (warnings.size() != (quantity)) {                                  \
      ASSERT_EQ(static_cast<size_t>(quantity), warnings.size()) << error; \
    }                                                                     \
  } while (0)

TEST(LintTests, BadConstNames) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

const bad_CONST uint64 = 1234;
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint());
  ASSERT_WARNINGS(1, library, "bad_CONST");
}

TEST(LintTests, BadConstNamesKconst) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

const kAllIsCalm uint64 = 1234;
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint());
  ASSERT_WARNINGS(1, library, "kAllIsCalm");
  const auto& warnings = library.lints();
  ASSERT_THAT(warnings[0], HasSubstr("ALL_IS_CALM"));
}

TEST(LintTests, GoodConstNames) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

const GOOD_CONST uint64 = 1234;
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_TRUE(library.Lint());
  ASSERT_WARNINGS(0, library, "");
}

TEST(LintTests, BadProtocolNames) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

protocol URLLoader {};
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint());
  ASSERT_WARNINGS(1, library, "URLLoader");
  const auto& warnings = library.lints();
  ASSERT_THAT(warnings[0], HasSubstr("UrlLoader"));
}

TEST(LintTests, GoodProtocolNames) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

protocol UrlLoader {};
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_TRUE(library.Lint());
  ASSERT_WARNINGS(0, library, "");
}

TEST(LintTests, BadLibraryNamesBannedName) {
  TestLibrary library(R"FIDL(
library fuchsia.zxsocket;
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint());
  ASSERT_WARNINGS(1, library, "zxsocket");
}

TEST(LintTests, BadUsingNames) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

using zx as bad_USING;

alias Unused = bad_USING.Handle;
)FIDL");
  library.UseLibraryZx();
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint());
  ASSERT_WARNINGS(1, library, "bad_USING");
}

TEST(LintTests, GoodUsingNames) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

using zx as good_using;

alias Unused = good_using.Handle;
)FIDL");
  library.UseLibraryZx();
  ASSERT_COMPILED(library);
  ASSERT_TRUE(library.Lint());
  ASSERT_WARNINGS(0, library, "");
}

TEST(LintTests, BadAliasNames) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

alias snake_case = uint32;
)FIDL");
  library.UseLibraryZx();
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint());
  ASSERT_WARNINGS(1, library, "snake_case");
}

TEST(LintTests, GoodAliasNames) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

alias SnakeCase = uint32;
)FIDL");
  library.UseLibraryZx();
  ASSERT_COMPILED(library);
  ASSERT_TRUE(library.Lint());
  ASSERT_WARNINGS(0, library, "");
}

// TODO(https://fxbug.dev/42158155): Delete this test once new-types are supported.
// This is a case where compilation would fail, but since the linter only operates on the parsed
// raw AST, we would not yet know it. Thus, we expect compilation to fail, but linting to pass.
TEST(LintTests, GoodIgnoreNewTypes) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

type TransactionId = uint64;
)FIDL");
  ASSERT_FALSE(library.Compile());
  ASSERT_TRUE(library.Lint());
}

TEST(LintTests, GoodProtocolOpenness) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

open protocol OpenExample {};
ajar protocol AjarExample {};
closed protocol ClosedExample {};
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_TRUE(library.Lint({.included_check_ids = {"explicit-openness-modifier"}}));
  ASSERT_WARNINGS(0, library, "");
}

TEST(LintTests, BadMissingProtocolOpenness) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

protocol Example {};
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint({.included_check_ids = {"explicit-openness-modifier"}}));
  ASSERT_WARNINGS(1, library, "Example must have an explicit openness modifier");
}

TEST(LintTests, GoodMethodStrictness) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

protocol DefaultOpenExample {
  strict Foo1();
  flexible Foo2();

  strict Bar1() -> ();
  flexible Bar2() -> ();

  strict -> OnBaz1();
  flexible -> OnBaz2();
};
open protocol OpenExample {
  strict Foo1();
  flexible Foo2();

  strict Bar1() -> ();
  flexible Bar2() -> ();

  strict -> OnBaz1();
  flexible -> OnBaz2();
};
ajar protocol AjarExample {
  strict Foo1();
  flexible Foo2();

  strict Bar() -> ();

  strict -> OnBaz1();
  flexible -> OnBaz2();
};
closed protocol ClosedExample {
  strict Foo();
  strict Bar() -> ();
  strict -> OnBaz();
};
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_TRUE(library.Lint({.included_check_ids = {"explicit-flexible-method-modifier"}}));
  ASSERT_WARNINGS(0, library, "");
}

TEST(LintTests, BadMissingOneWayMethodStrictness) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

open protocol Example {
  Foo();
};
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint({.included_check_ids = {"explicit-flexible-method-modifier"}}));
  ASSERT_WARNINGS(1, library, "Foo must have an explicit 'flexible' modifier");
}

TEST(LintTests, BadMissingTwoWayMethodStrictness) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

open protocol Example {
  Foo() -> ();
};
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint({.included_check_ids = {"explicit-flexible-method-modifier"}}));
  ASSERT_WARNINGS(1, library, "Foo must have an explicit 'flexible' modifier");
}

TEST(LintTests, BadMissingEventStrictness) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

open protocol Example {
  -> OnFoo();
};
)FIDL");
  ASSERT_COMPILED(library);
  ASSERT_FALSE(library.Lint({.included_check_ids = {"explicit-flexible-method-modifier"}}));
  ASSERT_WARNINGS(1, library, "OnFoo must have an explicit 'flexible' modifier");
}

TEST(LintTests, BadMissingMethodStrictnessClosedProtocol) {
  // A closed protocol with missing method strictness won't compile, but the
  // linter will still emit a warning as well.
  TestLibrary library(R"FIDL(
library fuchsia.a;

closed protocol Example {
  Foo();
};
)FIDL");
  library.ExpectFail(ErrFlexibleOneWayMethodInClosedProtocol, "one-way method");
  ASSERT_COMPILER_DIAGNOSTICS(library);
  ASSERT_FALSE(library.Lint({.included_check_ids = {"explicit-flexible-method-modifier"}}));
  ASSERT_WARNINGS(1, library, "Foo must have an explicit 'flexible' modifier");
}

TEST(LintTests, BadMissingEventStrictnessClosedProtocol) {
  // A closed protocol with missing event strictness won't compile, but the
  // linter will still emit a warning as well.
  TestLibrary library(R"FIDL(
library fuchsia.a;

closed protocol Example {
  -> OnFoo();
};
)FIDL");
  library.ExpectFail(ErrFlexibleOneWayMethodInClosedProtocol, "event");
  ASSERT_COMPILER_DIAGNOSTICS(library);
  ASSERT_FALSE(library.Lint({.included_check_ids = {"explicit-flexible-method-modifier"}}));
  ASSERT_WARNINGS(1, library, "OnFoo must have an explicit 'flexible' modifier");
}

// These libraries won't compile because they're trying to use `zx`, but we can
// still check that the invalid uses of zx types triggers lints.
TEST(LintTests, ZxTypesStructField) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

type MyStruct = struct {
  foo zx.Status;
  bar zx.Result;
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesParameterStructField) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

type MyParamStruct = struct {
  foo vector<zx.Status>:10;
  bar vector<zx.Result>:10;
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesInlineStructField) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

type MyStruct = struct {
  foo struct {
    bar zx.Status;
  };
  bar struct {
    foo zx.Result;
  };
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesTableField) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

type MyTable = table {
  1: foo zx.Status;
  2: bar zx.Result;
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesParameterTableField) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

type MyParamTable = table {
  1: foo vector<zx.Status>:10;
  2: bar vector<zx.Result>:10;
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesUnionField) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

type MyUnion = strict union {
  1: foo zx.Status;
  2: bar zx.Result;
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesParameterUnionField) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

type MyParamUnion = strict union {
  1: foo vector<zx.Status>:10;
  2: bar vector<zx.Result>:10;
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesMethodParameters) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

closed protocol Example {
  Foo(struct {
    foo zx.Status;
    bar zx.Result;
  });
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesMethodReturn) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

closed protocol Example {
  Foo() -> (struct {
    foo zx.Status;
    bar zx.Result;
  });
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Consider using zx.Result if the status can be OK");
}

TEST(LintTests, ZxTypesError) {
  TestLibrary library(R"FIDL(
library fuchsia.a;

closed protocol Example {
  Foo() -> () error zx.Status;
  Bar() -> () error zx.Result;
};
)FIDL");
  ASSERT_FALSE(library.Lint({.included_check_ids = {"zx-status-non-error", "zx-result-error"}}));
  ASSERT_WARNINGS(1, library, "Use zx.Status for two-way errors instead of zx.Result");
}
}  // namespace
}  // namespace fidlc
