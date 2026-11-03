// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Explicit-tool API diagnostic; link against the LLVM Object/Support under test.
#include "llvm/Object/CTF.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Support/Compression.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstdlib>

using namespace llvm;
using namespace llvm::object;
using namespace llvm::ELF;

static unsigned Checks;
static void check(bool Passed) {
  ++Checks;
  if (!Passed) {
    errs() << "CTF API check failed: " << Checks << '\n';
    std::exit(1);
  }
}

int main() {
  for (unsigned Version : {2u, 3u})
    for (auto Endian : {llvm::endianness::little, llvm::endianness::big})
      for (bool Compressed : {false, true}) {
        unsigned Width = Version == 2 ? 2 : 4;
        SmallVector<uint8_t, 0> Data(36, 0), Body(5, 0), Payload;
        support::endian::write16(Data.data(), 0xcff1, Endian);
        Data[2] = Version;
        Data[3] = Compressed;
        support::endian::write32(Data.data() + 20, Width, Endian);
        support::endian::write32(Data.data() + 24, 4, Endian);
        support::endian::write32(Data.data() + 28, 4, Endian);
        support::endian::write32(Data.data() + 32, 1, Endian);
        if (Compressed)
          compression::zlib::compress(Body, Payload);
        else
          Payload = Body;
        Data.append(Payload);
        SmallVector<CTFSymbolTable::Symbol, 0> Input{{10, STT_OBJECT}};
        auto Parsed = CTFSymbolTable::create(Data, Input);
        check(bool(Parsed));
        // Own bytes and offsets must survive destruction of input and moves.
        Data.clear();
        CTFSymbolTable Moved = std::move(*Parsed);
        CTFSymbolTable Table = Moved;
        SmallVector<uint8_t, 0> Out{0xa5};
        auto Same = Table.rewrite(Input, Out);
        check(Same && !*Same && Out == SmallVector<uint8_t, 0>{0xa5});
        auto Reject = [&](ArrayRef<CTFSymbolTable::Symbol> Symbols) {
          auto Size = Table.getUncompressedRewrittenSize(Symbols);
          check(!Size);
          consumeError(Size.takeError());
          auto Result = Table.rewrite(Symbols, Out);
          check(!Result);
          consumeError(Result.takeError());
          check(Out == SmallVector<uint8_t, 0>{0xa5});
        };
        Reject({{10, STT_FUNC}});
        Reject({{11, STT_OBJECT}});
        Reject({{10, STT_OBJECT}, {10, STT_OBJECT}});
        Reject({{CTFSymbolTable::NewSymbol, STT_NOTYPE}});
        // Payload is identical; only the object/function boundary changes.
        SmallVector<CTFSymbolTable::Symbol, 0> Functions{{CTFSymbolTable::NewSymbol, STT_FUNC}};
        auto Changed = Table.rewrite(Functions, Out);
        check(Changed && *Changed);
        check(support::endian::read32(Out.data() + 20, Endian) == 0);
        auto Reparsed = CTFSymbolTable::create(Out, {{20, STT_FUNC}});
        check(bool(Reparsed));
        if (!Reparsed) { consumeError(Reparsed.takeError()); return 1; }
        // A repeated new-symbol sentinel is valid only in the output.
        auto Added = Table.rewrite({{CTFSymbolTable::NewSymbol, STT_OBJECT},
                                   {CTFSymbolTable::NewSymbol, STT_FUNC},
                                   {CTFSymbolTable::NewSymbol, STT_FUNC}}, Out);
        check(Added && *Added);
        auto Duplicate = CTFSymbolTable::create(Out, {{20, STT_OBJECT}, {20, STT_FUNC}});
        check(!Duplicate);
        consumeError(Duplicate.takeError());
        auto Reserved = CTFSymbolTable::create(Out, {{CTFSymbolTable::NewSymbol, STT_OBJECT}});
        check(!Reserved);
        consumeError(Reserved.takeError());
        auto InvalidType = CTFSymbolTable::create(Out, {{20, STT_NOTYPE}});
        check(!InvalidType);
        consumeError(InvalidType.takeError());
        auto Removed = Table.rewrite({}, Out);
        check(Removed && *Removed);
        check(support::endian::read32(Out.data() + 24, Endian) == 0);
        auto Empty = CTFSymbolTable::create(Out, {});
        check(bool(Empty));
        if (!Empty) { consumeError(Empty.takeError()); return 1; }
      }
  // Plan section sizes independently of final symbol ordering. Exercise known
  // packed function records of odd/even lengths and a nonempty label prefix.
  for (unsigned Version : {2u, 3u})
    for (auto Endian : {llvm::endianness::little, llvm::endianness::big})
      for (bool Compressed : {false, true}) {
        unsigned Width = Version == 2 ? 2 : 4;
        SmallVector<uint8_t, 0> Data(36, 0), Body(8, 0), Payload;
        auto Add = [&](uint32_t V) {
          size_t At = Body.size();
          Body.resize(At + Width);
          if (Width == 2)
            support::endian::write16(Body.data() + At, V, Endian);
          else
            support::endian::write32(Body.data() + At, V, Endian);
        };
        Add(0); // Object association.
        for (unsigned Count : {0u, 1u, 2u}) {
          Add(5u << (Width == 2 ? 11 : 26) | Count);
          for (unsigned I = 0; I != Count + 1; ++I)
            Add(0); // Return/argument unknown references.
        }
        Add(0); // Unknown function association.
        while (Body.size() % 4)
          Body.push_back(0);
        unsigned TypeOffset = Body.size();
        Body.push_back(0); // Required empty string.
        support::endian::write16(Data.data(), 0xcff1, Endian);
        Data[2] = Version;
        Data[3] = Compressed;
        for (auto [At, V] : {std::pair<unsigned, unsigned>{16, 8},
                            {20, 8 + Width}, {24, TypeOffset},
                            {28, TypeOffset}, {32, 1}})
          support::endian::write32(Data.data() + At, V, Endian);
        if (Compressed)
          compression::zlib::compress(Body, Payload);
        else
          Payload = Body;
        Data.append(Payload);
        SmallVector<CTFSymbolTable::Symbol, 0> Input{
            {10, STT_OBJECT}, {20, STT_FUNC}, {21, STT_FUNC},
            {22, STT_FUNC}, {23, STT_FUNC}};
        auto Parsed = CTFSymbolTable::create(Data, Input);
        check(bool(Parsed));
        if (!Parsed) { consumeError(Parsed.takeError()); return 1; }
        SmallVector<CTFSymbolTable::Symbol, 0> Reverse(Input);
        std::reverse(Reverse.begin(), Reverse.end());
        for (const auto &Symbols : {
                 Input, Reverse, SmallVector<CTFSymbolTable::Symbol, 0>{},
                 SmallVector<CTFSymbolTable::Symbol, 0>{{21, STT_FUNC}},
                 SmallVector<CTFSymbolTable::Symbol, 0>{
                     {CTFSymbolTable::NewSymbol, STT_OBJECT}, {22, STT_FUNC},
                     {CTFSymbolTable::NewSymbol, STT_FUNC},
                     {CTFSymbolTable::NewSymbol, STT_FUNC}}}) {
          auto Planned = Parsed->getUncompressedRewrittenSize(Symbols);
          check(bool(Planned));
          SmallVector<uint8_t, 0> Out;
          auto Changed = Parsed->rewrite(Symbols, Out);
          check(bool(Changed));
          if (!Planned || !Changed) return 1;
          ArrayRef<uint8_t> Encoded = *Changed ? ArrayRef<uint8_t>(Out)
                                              : ArrayRef<uint8_t>(Data);
          SmallVector<uint8_t, 0> Decoded;
          if (Compressed) {
            uint64_t Size = uint64_t(support::endian::read32(Encoded.data() + 28, Endian)) +
                            support::endian::read32(Encoded.data() + 32, Endian);
            if (Error E = compression::zlib::decompress(Encoded.drop_front(36), Decoded, Size)) {
              consumeError(std::move(E));
              check(false);
            }
          } else {
            Decoded.append(Encoded.begin() + 36, Encoded.end());
          }
          check(*Planned == 36 + Decoded.size());
        }
        auto A = Parsed->getUncompressedRewrittenSize(Input);
        auto B = Parsed->getUncompressedRewrittenSize(Reverse);
        check(A && B && *A == *B);
      }
  outs() << Checks << " CTF API checks passed\n";
}
