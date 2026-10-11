/* SPDX-License-Identifier: BSD-2-Clause */
/* Independent raw-socket counterpart to the Scapy MLD group fixture. */
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <err.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
    struct sockaddr_in6 src = { .sin6_len = sizeof(src), .sin6_family = AF_INET6 };
    struct sockaddr_in6 dst = { .sin6_len = sizeof(dst), .sin6_family = AF_INET6 };
    struct mld_hdr mld = {0};
    unsigned char options[8] = { IPPROTO_ICMPV6, 0, 5, 2, 0, 0, 1, 0 };
    unsigned int index;
    int fd, hops = 1;

    if (argc != 4 || access("/root/pf-parity-disposable", F_OK) != 0)
        errx(1, "requires disposable guest marker, interface, query/report, group");
    if ((index = if_nametoindex(argv[1])) == 0)
        errx(1, "unknown interface");
    if (strcmp(argv[2], "query") == 0)
        mld.mld_type = MLD_LISTENER_QUERY;
    else if (strcmp(argv[2], "report") == 0)
        mld.mld_type = MLD_LISTENER_REPORT;
    else
        errx(1, "invalid message type");
    if (inet_pton(AF_INET6, argv[3], &mld.mld_addr) != 1)
        errx(1, "invalid group");
    inet_pton(AF_INET6, "fe80::1234", &src.sin6_addr);
    inet_pton(AF_INET6, "ff02::1", &dst.sin6_addr);
    src.sin6_scope_id = dst.sin6_scope_id = index;
    if ((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1)
        err(1, "socket");
    if (bind(fd, (struct sockaddr *)&src, sizeof(src)) == -1 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index)) == -1 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) == -1 ||
        setsockopt(fd, IPPROTO_IPV6, IPV6_HOPOPTS, options, sizeof(options)) == -1)
        err(1, "socket setup");
    if (sendto(fd, &mld, sizeof(mld), 0, (struct sockaddr *)&dst, sizeof(dst)) != sizeof(mld))
        err(1, "sendto");
    close(fd);
    return (0);
}
