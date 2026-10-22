/* SPDX-License-Identifier: BSD-2-Clause */
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <system_error>
#include <unistd.h>
#include "dtraced_config.h"
#include "dtraced_directory.h"
#include "dtraced_state.h"
int main() {
    unsigned long count = 7;
    for (const char *bad : {"", "0", "-1", "+1", " 1", "1x", "1 ", "1025", "999999999999999999999999"}) {
        assert(!dtraced::parse_workers(bad, count)); assert(count == 7);
    }
    errno = ERANGE;
    assert(dtraced::parse_workers("16", count) && count == 16);
    assert(dtraced::parse_workers("1024", count) && count == 1024);
    char base[32] = "unchanged", in[32] = "unchanged", out[32] = "unchanged", local[32] = "unchanged";
    for (const auto &bad : {std::string(""), std::string("relative"), std::string("/") + std::string(31, 'x'), std::string("/") + std::string(23, 'x')}) {
        assert(!dtraced::directory_paths(bad.c_str(), base, in, out, local));
        assert(strcmp(base, "unchanged") == 0 && strcmp(in, "unchanged") == 0 && strcmp(out, "unchanged") == 0 && strcmp(local, "unchanged") == 0);
    }
    std::string limit = "/" + std::string(20, 'x');
    assert(dtraced::directory_paths(limit.c_str(), base, in, out, local)); assert(strlen(out) == 31);
    assert(dtraced::directory_paths("/var/test///", base, in, out, local));
    assert(strcmp(base, "/var/test") == 0 && strcmp(out, "/var/test/outbound/") == 0);
    assert(dtraced::directory_paths("/", base, in, out, local)); assert(strcmp(in, "/inbound/") == 0);
    bool failed = false;
    try {
        dtraced::dir bad("/dev/null/child", &dtraced::process_outbound);
    } catch (const std::system_error &e) {
        failed = true;
        assert(e.code().value() == ENOTDIR);
    }
    assert(failed);
    char previous[MAXPATHLEN];
    strlcpy(previous, dtraced::OUTBOUNDDIR, sizeof(previous));
    strlcpy(dtraced::OUTBOUNDDIR, "/dev/null/child", sizeof(dtraced::OUTBOUNDDIR));
    dtraced::state state{};
    const char *argv[] = {"dtraced", nullptr};
    assert(!state.initialize(1, 0, 1, argv));
    assert(state.outbounddir == nullptr && state.inbounddir == nullptr);
    assert(state.basedir == nullptr && state.socket() == -1);
    strlcpy(dtraced::OUTBOUNDDIR, previous, sizeof(dtraced::OUTBOUNDDIR));
    char temp[] = "/tmp/hypertrace-init-XXXXXX";
    assert(mkdtemp(temp) != nullptr);
    char previous_in[MAXPATHLEN];
    strlcpy(previous_in, dtraced::INBOUNDDIR, sizeof(previous_in));
    strlcpy(dtraced::OUTBOUNDDIR, temp, sizeof(dtraced::OUTBOUNDDIR));
    strlcpy(dtraced::INBOUNDDIR, "/dev/null/child", sizeof(dtraced::INBOUNDDIR));
    auto open_fds = [] {
        unsigned n = 0;
        for (int fd = 0; fd < 1024; ++fd)
            if (fcntl(fd, F_GETFD) != -1) ++n;
        return n;
    };
    unsigned before = open_fds();
    dtraced::state partial{};
    assert(!partial.initialize(1, 0, 1, argv));
    assert(partial.outbounddir == nullptr && partial.inbounddir == nullptr);
    assert(open_fds() == before);
    strlcpy(dtraced::OUTBOUNDDIR, previous, sizeof(dtraced::OUTBOUNDDIR));
    strlcpy(dtraced::INBOUNDDIR, previous_in, sizeof(dtraced::INBOUNDDIR));
    assert(rmdir(temp) == 0);
    puts("PASS: bounded paths and worker counts; directory-open failure leaves daemon unstarted");
}
