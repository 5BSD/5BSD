//===- CTF.cpp - CTF symbol associations -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Object/CTF.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Support/Compression.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/MathExtras.h"

using namespace llvm;
using namespace llvm::object;
using namespace llvm::ELF;

static Error invalid(StringRef Reason) {
  return createStringError(errc::invalid_argument,
                           "invalid .SUNW_ctf: " + Reason);
}

uint32_t CTFSymbolTable::read32(ArrayRef<uint8_t> Data, size_t Offset) const {
  return support::endian::read32(Data.data() + Offset, Endian);
}

uint32_t CTFSymbolTable::readID(size_t Offset) const {
  return Width == 4 ? read32(Body, Offset)
                    : support::endian::read16(Body.data() + Offset, Endian);
}

Expected<CTFSymbolTable>
CTFSymbolTable::create(ArrayRef<uint8_t> Data, ArrayRef<Symbol> InputSymbols) {
  CTFSymbolTable Table;
  if (Error E = Table.parse(Data, InputSymbols))
    return std::move(E);
  return Table;
}

Error CTFSymbolTable::parse(ArrayRef<uint8_t> Data,
                           ArrayRef<Symbol> InputSymbols) {
  if (Data.size() < 36)
    return invalid("truncated header");
  if (support::endian::read16le(Data.data()) == 0xcff1)
    Endian = llvm::endianness::little;
  else if (support::endian::read16be(Data.data()) == 0xcff1)
    Endian = llvm::endianness::big;
  else
    return invalid("bad magic");
  if (Data[2] != 2 && Data[2] != 3)
    return invalid("unsupported version");
  if (Data[3] & ~1)
    return invalid("unsupported flags");
  Width = Data[2] == 3 ? 4 : 2;
  Compressed = Data[3] & 1;
  Header.assign(Data.begin(), Data.begin() + 36);
  ObjectOffset = read32(Header, 16);
  FunctionOffset = read32(Header, 20);
  TypeOffset = read32(Header, 24);
  uint32_t LabelOffset = read32(Header, 12);
  uint32_t StringOffset = read32(Header, 28);
  uint64_t Size = uint64_t(StringOffset) + read32(Header, 32);
  if (Size > UINT32_MAX || LabelOffset > ObjectOffset ||
      ObjectOffset > FunctionOffset || FunctionOffset > TypeOffset ||
      TypeOffset > StringOffset || (LabelOffset & 3) ||
      ObjectOffset % Width || FunctionOffset % Width || (TypeOffset & 3))
    return invalid("invalid subsection offsets");
  if (Compressed) {
    if (!compression::zlib::isAvailable())
      return invalid("zlib is unavailable");
    if (Error E = compression::zlib::decompress(Data.drop_front(36), Body, Size))
      return E;
  } else {
    if (Size != Data.size() - 36)
      return invalid("incorrect payload size");
    Body.assign(Data.begin() + 36, Data.end());
  }
  if (Body.size() != Size)
    return invalid("incorrect decompressed size");
  uint32_t O = ObjectOffset, F = FunctionOffset;
  for (auto [Index, Type] : InputSymbols) {
    if (Type != STT_OBJECT && Type != STT_FUNC)
      return invalid("invalid input symbol type");
    if (Index == NewSymbol || Entries.count(Index))
      return invalid("duplicate or reserved input symbol identity");
    uint32_t &Offset = Type == STT_OBJECT ? O : F;
    uint32_t End = Type == STT_OBJECT ? FunctionOffset : TypeOffset;
    if (End - Offset < Width)
      return invalid("missing symbol type record");
    uint64_t Length = Width;
    if (Type == STT_FUNC) {
      uint32_t Info = readID(Offset);
      uint32_t Kind = Width == 4 ? Info >> 26 : Info >> 11;
      uint32_t Count = Info & (Width == 4 ? 0xffffff : 0x3ff);
      if (Info != 0) {
        if (Kind != 5)
          return invalid("invalid function type record");
        // Function-section records are packed; only the following
        // type section requires four-byte alignment.
        Length = uint64_t(Count + 2) * Width;
      }
    }
    if (Length > End - Offset)
      return invalid("truncated symbol type record");
    // Offsets remain valid when this owning object is moved or copied.
    Entries[Index] = {Offset, uint32_t(Length), Type};
    Offset += Length;
  }
  // Version 2 can have a final half-word of zero alignment padding.
  auto Padding = [&](uint32_t Begin, uint32_t End) {
    return End - Begin < 4 &&
           llvm::all_of(ArrayRef<uint8_t>(Body).slice(Begin, End - Begin),
                        [](uint8_t V) { return V == 0; });
  };
  if (!Padding(O, FunctionOffset) || !Padding(F, TypeOffset))
    return invalid("symbol/type table length mismatch");
  return Error::success();
}

Expected<bool> CTFSymbolTable::rewrite(ArrayRef<Symbol> OutputSymbols,
                                       SmallVectorImpl<uint8_t> &Out) const {
  DenseSet<uint64_t> Seen;
  for (auto [Index, Type] : OutputSymbols) {
    if (Type != STT_OBJECT && Type != STT_FUNC)
      return invalid("invalid output symbol type");
    if (Index == NewSymbol)
      continue;
    auto I = Entries.find(Index);
    if (I == Entries.end())
      return invalid("unknown output symbol identity");
    if (I->second.Type != Type)
      return invalid("output symbol type changed");
    if (!Seen.insert(Index).second)
      return invalid("duplicate output symbol identity");
  }
  SmallVector<uint8_t, 0> Updated(Body.begin(), Body.begin() + ObjectOffset);
  auto Append = [&](unsigned Type) {
    for (auto [Index, Kind] : OutputSymbols) {
      if (Kind != Type)
        continue;
      if (Index == NewSymbol) {
        Updated.append(Width, 0);
      } else {
        const Entry &E = Entries.find(Index)->second;
        Updated.append(Body.begin() + E.Offset, Body.begin() + E.Offset + E.Length);
      }
    }
  };
  Append(STT_OBJECT);
  Updated.resize(alignTo(Updated.size(), Width), 0);
  uint64_t NewFunctions = Updated.size();
  Append(STT_FUNC);
  Updated.resize(alignTo(Updated.size(), 4), 0);
  uint64_t NewTypes = Updated.size();
  Updated.append(Body.begin() + TypeOffset, Body.end());
  uint64_t NewStrings = NewTypes + (read32(Header, 28) - TypeOffset);
  if (Updated.size() > UINT32_MAX || NewStrings > UINT32_MAX)
    return invalid("rewritten payload is too large");
  if (Updated == Body && NewFunctions == FunctionOffset &&
      NewTypes == TypeOffset && NewStrings == read32(Header, 28))
    return false;
  SmallVector<uint8_t, 0> NewHeader(Header);
  support::endian::write32(NewHeader.data() + 20, NewFunctions, Endian);
  support::endian::write32(NewHeader.data() + 24, NewTypes, Endian);
  support::endian::write32(NewHeader.data() + 28, NewStrings, Endian);
  SmallVector<uint8_t, 0> Payload;
  if (Compressed)
    compression::zlib::compress(Updated, Payload);
  else
    Payload = std::move(Updated);
  NewHeader.append(Payload);
  Out.assign(NewHeader.begin(), NewHeader.end());
  return true;
}
