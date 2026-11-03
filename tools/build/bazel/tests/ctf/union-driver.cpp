// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Explicit-tool fixture driver, not a production linker or build frontend.
#include "llvm/Object/CTF.h"
#include "llvm/ADT/StringExtras.h"

#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
#include <memory>

using namespace llvm;
using namespace llvm::object;

int main(int Argc, char **Argv) {
  // OUT OUTPUT_SYMBOLS ENDIAN COMPRESS (CTF INPUT_SYMBOLS EXTERNAL_STRINGS)...
  if (Argc < 8 || (Argc - 5) % 3 ||
      (StringRef(Argv[3]) != "le" && StringRef(Argv[3]) != "be") ||
      (StringRef(Argv[4]) != "raw" && StringRef(Argv[4]) != "z")) return 2;
  SmallVector<CTFSymbolTable, 0> Inputs;
  SmallVector<std::unique_ptr<MemoryBuffer>, 0> ExternalStorage;
  SmallVector<ArrayRef<uint8_t>, 0> External;
  for (int I = 5; I < Argc; I += 3) {
    auto Data = MemoryBuffer::getFile(Argv[I]);
    auto Strings = MemoryBuffer::getFile(Argv[I + 2]);
    if (!Data || !Strings) return 3;
    std::ifstream Symbols(Argv[I + 1]);
    SmallVector<CTFSymbolTable::Symbol, 0> Identities;
    uint32_t Index, Type;
    while (Symbols >> Index >> Type) {
      if (Type > UINT8_MAX) return 4;
      Identities.push_back({Index, uint8_t(Type)});
    }
    if (!Symbols.eof()) return 4;
    auto Parsed = CTFSymbolTable::create(arrayRefFromStringRef((*Data)->getBuffer()), Identities);
    if (!Parsed) { errs() << toString(Parsed.takeError()) << '\n'; return 5; }
    Inputs.push_back(std::move(*Parsed));
    External.push_back(arrayRefFromStringRef((*Strings)->getBuffer()));
    ExternalStorage.push_back(std::move(*Strings));
  }
  SmallVector<CTFSymbolTable::SymbolReference, 0> Outputs;
  std::ifstream Symbols(Argv[2]);
  uint32_t Input, Index, Type;
  while (Symbols >> Input >> Index >> Type) {
    if (Type > UINT8_MAX) return 6;
    Outputs.push_back({Input, Index, uint8_t(Type)});
  }
  if (!Symbols.eof()) return 6;
  SmallVector<uint8_t, 0> Out{0xa5};
  auto Endian = StringRef(Argv[3]) == "le" ? llvm::endianness::little : llvm::endianness::big;
  if (Error E = CTFSymbolTable::merge(Inputs, External, Outputs, Endian,
                                     StringRef(Argv[4]) == "z", Out)) {
    errs() << toString(std::move(E)) << '\n';
    if (Out != SmallVector<uint8_t, 0>{0xa5}) return 7;
    return 8;
  }
  std::error_code EC;
  raw_fd_ostream Stream(Argv[1], EC);
  if (EC) return 9;
  Stream.write(reinterpret_cast<const char *>(Out.data()), Out.size());
  Stream.close();
  return Stream.has_error() ? 10 : 0;
}
