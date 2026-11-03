//===- CTF.h - CTF symbol associations ---------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBJECT_CTF_H
#define LLVM_OBJECT_CTF_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"
#include <cstdint>
#include <utility>

namespace llvm {
namespace object {

/// Reorder SUNW CTF symbol associations using original symbol identities.
/// Owns container bytes. Symbol rewriting keeps type/string/label bytes opaque;
/// namespace union relocates supported self-contained type graphs explicitly.
/// Callers select eligible defined symbols in symbol-table order, retain exact
/// input-file/index provenance, and validate ELF section links.
class CTFSymbolTable {
public:
  // Original symbol index and ELF STT_OBJECT/STT_FUNC type. Identities are local
  // to this container, not names or indices from a different input file.
  using Symbol = std::pair<uint32_t, uint8_t>;
  static constexpr uint32_t NewSymbol = UINT32_MAX;

  LLVM_ABI static Expected<CTFSymbolTable>
  create(ArrayRef<uint8_t> Data, ArrayRef<Symbol> InputSymbols);

  /// New symbols use NewSymbol; all other identities must come from create().
  /// Return false without touching Out if bytes are unchanged. Errors also
  /// leave Out unchanged. A true result replaces Out with the new container.
  LLVM_ABI Expected<bool> rewrite(ArrayRef<Symbol> OutputSymbols,
                                  SmallVectorImpl<uint8_t> &Out) const;

  struct SymbolReference {
    uint32_t Input, Index;
    uint8_t Type;
  };

  /// Form a disjoint v3 namespace union without name-based type deduplication.
  /// ExternalStrings is each input ELF string table. Input identities remain
  /// scoped by input container. Output endianness and compression are explicit.
  /// Supports self-contained dictionaries with no labels or matching labels
  /// that cover each entire dictionary. Parents and unrepresentable label
  /// scopes fail explicitly. On error Out remains unchanged.
  LLVM_ABI static Error merge(ArrayRef<CTFSymbolTable> Inputs,
                              ArrayRef<ArrayRef<uint8_t>> ExternalStrings,
                              ArrayRef<SymbolReference> OutputSymbols,
                              llvm::endianness OutputEndian, bool Compress,
                              SmallVectorImpl<uint8_t> &Out);

private:
  struct Entry {
    uint32_t Offset, Length;
    uint8_t Type;
  };
  SmallVector<uint8_t, 0> Header, Body;
  // Widen indices so no uint32_t identity aliases DenseMap's sentinel keys.
  DenseMap<uint64_t, Entry> Entries;
  llvm::endianness Endian = llvm::endianness::little;
  uint32_t ObjectOffset = 0, FunctionOffset = 0, TypeOffset = 0;
  unsigned Width = 0;
  bool Compressed = false;

  Error parse(ArrayRef<uint8_t> Data, ArrayRef<Symbol> InputSymbols);
  uint32_t read32(ArrayRef<uint8_t> Data, size_t Offset) const;
  uint32_t readID(size_t Offset) const;
};

} // namespace object
} // namespace llvm

#endif // LLVM_OBJECT_CTF_H
