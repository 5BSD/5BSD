// SPDX-License-Identifier: BSD-2-Clause
// Regression coverage for the native FIDL compiler port.
#include <gtest/gtest.h>
#include "tools/fidl/fidlc/src/lexer.h"
#include "tools/fidl/fidlc/src/source_file.h"

TEST(BsdLexer, StartOfFileHasBackingStorage) {
  for (const char* text : {"", "library example;", "\n\nlibrary example;\n"}) {
    fidlc::SourceFile source("example.fidl", text);
    fidlc::Reporter reporter;
    fidlc::Lexer lexer(source, &reporter);
    auto token = lexer.Lex();
    EXPECT_EQ(token.kind(), fidlc::Token::Kind::kStartOfFile);
    ASSERT_TRUE(token.span().valid());
    EXPECT_EQ(token.ptr(), source.data().data());
    EXPECT_EQ(token.data().size(), 0u);
    EXPECT_EQ(token.span().position().line, 1);
    EXPECT_EQ(token.span().position().column, 1);
  }
}
