/* SPDX-License-Identifier: BSD-2-Clause */
#include "lldb/API/SBDebugger.h"
#include "lldb/API/SBError.h"
#include "lldb/API/SBStringList.h"
#include "lldb/API/SBStructuredData.h"
#include "lldb/Version/Version.inc"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <limits.h>
#include <link.h>
#define CHECK(c) do { if (!(c)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #c); return 1; } } while (0)
struct ExpectedLibraries {
    char paths[3][PATH_MAX];
    bool found[3]{};
    bool mismatch = false;
};
static const char *filename(const char *path) {
    const char *slash = std::strrchr(path, '/');
    return slash == nullptr ? path : slash + 1;
}
static int inspect_library(struct dl_phdr_info *info, size_t, void *opaque) {
    auto *expected = static_cast<ExpectedLibraries *>(opaque);
    char actual[PATH_MAX];
    if (info->dlpi_name[0] == '\0' || realpath(info->dlpi_name, actual) == nullptr)
        return 0;
    for (size_t i = 0; i < 3; ++i) {
        if (std::strcmp(filename(actual), filename(expected->paths[i])) != 0)
            continue;
        if (std::strcmp(actual, expected->paths[i]) != 0)
            expected->mismatch = true;
        else
            expected->found[i] = true;
        std::printf("loaded private library: %s\n", actual);
    }
    return 0;
}
int main(int argc, char **argv) {
    CHECK(argc == 4);
    CHECK(std::getenv("DTRACE_DOF_INIT_DISABLE") != nullptr);
    ExpectedLibraries expected;
    for (size_t i = 0; i < 3; ++i)
        CHECK(realpath(argv[i + 1], expected.paths[i]) != nullptr);
    CHECK(dl_iterate_phdr(inspect_library, &expected) == 0);
    CHECK(!expected.mismatch);
    CHECK(expected.found[0] && expected.found[1] && expected.found[2]);
    CHECK(std::strstr(lldb::SBDebugger::GetVersionString(), LLDB_VERSION_STRING) != nullptr);
    lldb::SBError error;
    CHECK(error.Success());
    error.SetErrorString("native-lldb-error");
    CHECK(error.Fail());
    lldb::SBError saved(error);
    error.Clear();
    CHECK(error.Success() && saved.Fail());
    CHECK(std::strcmp(saved.GetCString(), "native-lldb-error") == 0);
    lldb::SBStringList names;
    names.AppendString("first"); names.AppendString("second");
    lldb::SBStringList copied(names);
    names.Clear();
    CHECK(names.GetSize() == 0 && copied.GetSize() == 2);
    CHECK(std::strcmp(copied.GetStringAtIndex(0), "first") == 0);
    CHECK(std::strcmp(copied.GetStringAtIndex(1), "second") == 0);
    lldb::SBStructuredData data;
    CHECK(data.SetFromJSON("{\"answer\":42,\"enabled\":true,\"items\":[\"a\",\"b\"]}").Success());
    CHECK(data.IsValid() && data.GetSize() == 3);
    CHECK(data.GetValueForKey("answer").GetUnsignedIntegerValue() == 42);
    CHECK(data.GetValueForKey("enabled").GetBooleanValue());
    CHECK(data.GetValueForKey("items").GetSize() == 2);
    CHECK(!data.GetValueForKey("missing").IsValid());
    lldb::SBStructuredData invalid;
    CHECK(invalid.SetFromJSON("{broken").Fail());
    std::puts("LLDB API smoke PASS: native DSO, version, errors, strings and JSON; no debugger initialized");
    return 0;
}
