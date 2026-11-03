//===- CTFMerge.cpp - Relocate standalone SUNW CTF namespaces ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Object/CTF.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringMap.h"
#include <algorithm>
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Support/Compression.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/MathExtras.h"

using namespace llvm;
using namespace llvm::object;
using namespace llvm::ELF;

namespace {
Error invalid(StringRef Reason) {
  return createStringError(errc::invalid_argument,
                           "cannot merge .SUNW_ctf: " + Reason);
}

// A v3 serialized word, with explicit relocation provenance. All IDs are
// assigned before relocation, so cycles require no recursive graph traversal.
struct Word {
  enum Kind { Literal, Type, String };
  Kind Tag;
  uint32_t Value;
};
struct Namespace {
  SmallVector<Word, 0> Words;
  SmallVector<uint32_t, 0> Labels;
  uint32_t TypeCount = 0, TypeBase = 0;
  ArrayRef<uint8_t> Strings, External;
};

struct Reader {
  ArrayRef<uint8_t> Data;
  llvm::endianness Endian;
  uint64_t At, End;
  bool has(uint64_t Size) const { return Size <= End - At; }
  uint32_t get(unsigned Width) {
    assert(has(Width));
    uint32_t V = Width == 2 ? support::endian::read16(Data.data() + At, Endian)
                            : support::endian::read32(Data.data() + At, Endian);
    At += Width;
    return V;
  }
};

Expected<StringRef> getString(const Namespace &N, uint32_t ID) {
  ArrayRef<uint8_t> Data = ID >> 31 ? N.External : N.Strings;
  uint32_t Offset = ID & 0x7fffffff;
  if (Offset >= Data.size())
    return invalid("string reference is outside its input table");
  StringRef S(reinterpret_cast<const char *>(Data.data() + Offset),
              Data.size() - Offset);
  size_t End = S.find('\0');
  if (End == StringRef::npos)
    return invalid("unterminated input string");
  return S.take_front(End);
}

// Types become v3 records. Input member layouts depend on both version and
// size, so simply widening IDs or copying v2 payloads would corrupt layouts.
Error scanTypes(ArrayRef<uint8_t> Body, uint32_t Begin, uint32_t End,
                unsigned Width, llvm::endianness Endian, Namespace &N) {
  Reader R{Body, Endian, Begin, End};
  auto Add = [&](Word::Kind Kind, uint32_t V) { N.Words.push_back({Kind, V}); };
  while (R.At < R.End) {
    if (!R.has(4 + 2 * Width))
      return invalid("truncated input type header");
    uint32_t Name = R.get(4), Info = R.get(Width), SizeWord = R.get(Width);
    uint32_t Kind = Info >> (Width == 2 ? 11 : 26);
    bool Root = Info & (1u << (Width == 2 ? 10 : 25));
    uint32_t Count = Info & (Width == 2 ? 0x3ff : 0xffffff);
    if (Kind > 13 || (Width == 4 && (Info & (1u << 24))))
      return invalid("unsupported type kind or reserved info bit");
    bool Reference = Kind == 3 || Kind == 5 || Kind >= 10;
    bool HeaderKind = Reference || Kind == 9;
    uint64_t Size = SizeWord;
    if (!HeaderKind && SizeWord == (Width == 2 ? 0xffffu : UINT32_MAX)) {
      if (!R.has(8))
        return invalid("truncated extended type size");
      Size = uint64_t(R.get(4)) << 32;
      Size |= R.get(4);
    }
    Add(Word::String, Name);
    Add(Word::Literal, Kind << 26 | uint32_t(Root) << 25 | Count);
    Add(Reference ? Word::Type : Word::Literal,
        !HeaderKind && Size >= UINT32_MAX ? UINT32_MAX : uint32_t(Size));
    if (!HeaderKind && Size >= UINT32_MAX) {
      Add(Word::Literal, Size >> 32);
      Add(Word::Literal, Size);
    }
    if (Kind == 0) {
      if (Name || Root || Count || Size)
        return invalid("nonempty unknown type");
    } else if (Kind == 1 || Kind == 2) {
      if (Count > 1 || !R.has(4))
        return invalid("invalid scalar record");
      Add(Word::Literal, R.get(4));
    } else if (Kind == 4) {
      if (Count > 1 || !R.has(2 * Width + 4))
        return invalid("invalid array record");
      Add(Word::Type, R.get(Width));
      Add(Word::Type, R.get(Width));
      Add(Word::Literal, R.get(4));
    } else if (Kind == 5) {
      uint64_t Bytes = alignTo(uint64_t(Count) * Width, 4);
      if (!R.has(Bytes))
        return invalid("truncated function type");
      for (uint32_t I = 0; I != Count; ++I)
        Add(Word::Type, R.get(Width));
      for (uint64_t I = uint64_t(Count) * Width; I != Bytes; ++I)
        if (Body[R.At++] != 0)
          return invalid("nonzero function type padding");
    } else if (Kind == 6 || Kind == 7) {
      bool Long = Size >= (uint64_t(1) << (Width == 2 ? 13 : 29));
      unsigned MemberSize = Long ? 16 : 4 + 2 * Width;
      if (!R.has(uint64_t(MemberSize) * Count))
        return invalid("truncated structure members");
      for (uint32_t I = 0; I != Count; ++I) {
        Add(Word::String, R.get(4));
        Add(Word::Type, R.get(Width));
        uint64_t Offset;
        if (Long) {
          if (Width == 2 && R.get(2) != 0)
            return invalid("nonzero long-member padding");
          Offset = uint64_t(R.get(4)) << 32;
          Offset |= R.get(4);
        } else {
          Offset = R.get(Width);
        }
        if (Size >= (uint64_t(1) << 29)) {
          Add(Word::Literal, Offset >> 32);
          Add(Word::Literal, Offset);
        } else {
          if (Offset > UINT32_MAX)
            return invalid("member offset is not representable in v3");
          Add(Word::Literal, Offset);
        }
      }
    } else if (Kind == 8) {
      if (!R.has(uint64_t(Count) * 8))
        return invalid("truncated enumeration");
      for (uint32_t I = 0; I != Count; ++I) {
        Add(Word::String, R.get(4));
        Add(Word::Literal, R.get(4));
      }
    } else if (Count || (Kind == 9 && Size != 0 && Size != 6 && Size != 7 && Size != 8)) {
      return invalid("invalid reference or forward record");
    }
    if (++N.TypeCount >= (Width == 2 ? 0x8000u : 0x80000000u))
      return invalid("input type namespace exceeds its ID width");
  }
  return Error::success();
}
} // namespace

Error CTFSymbolTable::merge(ArrayRef<CTFSymbolTable> Inputs,
                            ArrayRef<ArrayRef<uint8_t>> ExternalStrings,
                            ArrayRef<SymbolReference> OutputSymbols,
                            llvm::endianness OutputEndian, bool Compress,
                            SmallVectorImpl<uint8_t> &Out) {
  if (Inputs.empty() || ExternalStrings.size() != Inputs.size())
    return invalid("missing input namespace or external-string table");
  SmallVector<Namespace, 0> Namespaces(Inputs.size());
  SmallVector<uint8_t, 0> Strings(1, 0), Types, Objects, Functions, Labels;
  SmallVector<StringRef, 0> LabelNames;
  uint64_t NumTypes = 0;
  auto Write = [&](SmallVectorImpl<uint8_t> &V, uint32_t W) {
    uint8_t Buffer[4];
    support::endian::write32(Buffer, W, OutputEndian);
    V.append(Buffer, Buffer + 4);
  };
  for (size_t I = 0; I != Inputs.size(); ++I) {
    const auto &T = Inputs[I];
    Namespace &N = Namespaces[I];
    if (T.read32(T.Header, 4) || T.read32(T.Header, 8))
      return invalid("parent dictionaries require explicit resolution");
    if (T.read32(T.Header, 12) || T.ObjectOffset % 8)
      return invalid("unsupported label-table layout");
    uint32_t StringOffset = T.read32(T.Header, 28);
    N.Strings = ArrayRef<uint8_t>(T.Body).drop_front(StringOffset);
    N.External = ExternalStrings[I];
    if (N.Strings.empty() || N.Strings.front() != 0 ||
        (!N.External.empty() && N.External.front() != 0))
      return invalid("input string table has no initial zero");
    N.TypeBase = NumTypes;
    if (Error E = scanTypes(T.Body, T.TypeOffset, StringOffset, T.Width, T.Endian, N))
      return E;
    NumTypes += N.TypeCount;
    if (NumTypes >= 0x80000000ull)
      return invalid("merged type namespace exceeds v3 parent ID range");
    SmallVector<StringRef, 0> CurrentLabels;
    for (uint32_t At = 0; At != T.ObjectOffset; At += 8) {
      uint32_t Name = T.read32(T.Body, At);
      if (T.read32(T.Body, At + 4) != N.TypeCount)
        return invalid("partial label scopes cannot be preserved by namespace union");
      auto S = getString(N, Name);
      if (!S)
        return S.takeError();
      CurrentLabels.push_back(*S);
      if (I == 0)
        N.Labels.push_back(Name);
    }
    llvm::sort(CurrentLabels);
    if (std::adjacent_find(CurrentLabels.begin(), CurrentLabels.end()) != CurrentLabels.end())
      return invalid("duplicate label name");
    if (I == 0)
      LabelNames = std::move(CurrentLabels);
    else if (CurrentLabels != LabelNames)
      return invalid("different label scopes cannot be preserved by namespace union");
  }
  StringMap<uint32_t> StringOffsets;
  StringOffsets[""] = 0;
  auto Relocate = [&](size_t Input, Word W) -> Expected<uint32_t> {
    const Namespace &N = Namespaces[Input];
    if (W.Tag == Word::Literal || !W.Value)
      return W.Value;
    if (W.Tag == Word::Type) {
      if (W.Value > N.TypeCount)
        return invalid("dangling or parent type reference");
      return N.TypeBase + W.Value;
    }
    auto S = getString(N, W.Value);
    if (!S)
      return S.takeError();
    auto It = StringOffsets.find(*S);
    if (It != StringOffsets.end())
      return It->second;
    if (uint64_t(Strings.size()) + S->size() + 1 > 0x80000000ull)
      return invalid("merged string table exceeds name-offset width");
    uint32_t Offset = Strings.size();
    StringOffsets[*S] = Offset;
    Strings.append(S->bytes_begin(), S->bytes_end());
    Strings.push_back(0);
    return Offset;
  };
  // Validate every source association, including symbols omitted by the
  // output link. A dangling input edge must not disappear through selection.
  for (size_t I = 0; I != Inputs.size(); ++I) {
    const auto &T = Inputs[I];
    for (auto Pair : T.Entries) {
      const Entry &E = Pair.second;
      uint32_t Info = T.readID(E.Offset);
      if (E.Type == STT_FUNC && !Info)
        continue;
      if (E.Type == STT_FUNC && T.Width == 4 && (Info & (1u << 24)))
        return invalid("reserved function association info bit");
      uint32_t First = E.Type == STT_OBJECT ? 0 : 1;
      uint32_t Count = E.Type == STT_OBJECT ? 1 :
          (Info & (T.Width == 2 ? 0x3ff : 0xffffff)) + 1;
      for (uint32_t J = 0; J != Count; ++J) {
        auto Ref = Relocate(I, {Word::Type, T.readID(E.Offset + (First + J) * T.Width)});
        if (!Ref)
          return Ref.takeError();
      }
    }
  }
  for (size_t I = 0; I != Inputs.size(); ++I)
    for (Word W : Namespaces[I].Words) {
      auto Value = Relocate(I, W);
      if (!Value)
        return Value.takeError();
      Write(Types, *Value);
    }
  for (uint32_t Name : Namespaces[0].Labels) {
    auto Value = Relocate(0, {Word::String, Name});
    if (!Value)
      return Value.takeError();
    Write(Labels, *Value);
    Write(Labels, NumTypes);
  }
  DenseSet<uint64_t> Seen;
  for (auto S : OutputSymbols) {
    if (S.Type != STT_OBJECT && S.Type != STT_FUNC)
      return invalid("invalid output symbol type");
    auto &Dest = S.Type == STT_OBJECT ? Objects : Functions;
    if (S.Index == NewSymbol) {
      Write(Dest, 0);
      continue;
    }
    if (S.Input >= Inputs.size())
      return invalid("unknown output namespace");
    const auto &T = Inputs[S.Input];
    auto It = T.Entries.find(S.Index);
    if (It == T.Entries.end() || It->second.Type != S.Type)
      return invalid("unknown or changed output symbol identity");
    if (!Seen.insert(uint64_t(S.Input) << 32 | S.Index).second)
      return invalid("duplicate output symbol identity");
    uint32_t At = It->second.Offset;
    auto AddRef = [&](uint32_t ID) -> Error {
      auto V = Relocate(S.Input, {Word::Type, ID});
      if (!V)
        return V.takeError();
      Write(Dest, *V);
      return Error::success();
    };
    if (S.Type == STT_OBJECT) {
      if (Error E = AddRef(T.readID(At)))
        return E;
    } else {
      uint32_t Info = T.readID(At);
      if (!Info) {
        Write(Dest, 0);
        continue;
      }
      if (T.Width == 4 && (Info & (1u << 24)))
        return invalid("reserved function association info bit");
      uint32_t Count = Info & (T.Width == 2 ? 0x3ff : 0xffffff);
      bool Root = Info & (1u << (T.Width == 2 ? 10 : 25));
      Write(Dest, 5u << 26 | uint32_t(Root) << 25 | Count);
      for (uint32_t J = 0; J != Count + 1; ++J)
        if (Error E = AddRef(T.readID(At + (J + 1) * T.Width)))
          return E;
    }
  }
  uint64_t Fun = uint64_t(Labels.size()) + Objects.size();
  uint64_t Typ = Fun + Functions.size(), Str = Typ + Types.size();
  if (Str + Strings.size() > UINT32_MAX)
    return invalid("merged payload exceeds header offsets");
  SmallVector<uint8_t, 0> Body, Header(36, 0), Payload;
  for (const auto *V : {&Labels, &Objects, &Functions, &Types, &Strings})
    Body.append(V->begin(), V->end());
  support::endian::write16(Header.data(), 0xcff1, OutputEndian);
  Header[2] = 3;
  Header[3] = Compress;
  for (auto Pair : {std::pair<unsigned, uint64_t>{16, Labels.size()},
                    {20, Fun}, {24, Typ}, {28, Str}, {32, Strings.size()}})
    support::endian::write32(Header.data() + Pair.first, Pair.second, OutputEndian);
  if (Compress) {
    if (!compression::zlib::isAvailable())
      return invalid("zlib is unavailable");
    compression::zlib::compress(Body, Payload);
  } else {
    Payload = std::move(Body);
  }
  Header.append(Payload);
  Out.assign(Header.begin(), Header.end());
  return Error::success();
}
