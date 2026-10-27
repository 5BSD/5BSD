/* SPDX-License-Identifier: BSD-2-Clause */
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); return 1; } } while (0)

int
main(void)
{
	/* Ethernet, IPv4, UDP; destination port 53, no payload. */
	unsigned char packet[42] = { [12] = 0x08, [13] = 0x00,
	    [14] = 0x45, [17] = 28, [22] = 64, [23] = 17,
	    [26] = 192, [27] = 0, [28] = 2, [29] = 1,
	    [30] = 192, [31] = 0, [32] = 2, [33] = 2,
	    [34] = 0x30, [35] = 0x39, [37] = 53, [39] = 8 };
	struct pcap_pkthdr header = { .ts = {123, 456},
	    .caplen = sizeof(packet), .len = sizeof(packet) };
	struct bpf_program filter;
	pcap_t *dead, *reader;
	pcap_dumper_t *dumper;
	struct pcap_pkthdr *read_header;
	const unsigned char *read_packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	FILE *file;

	dead = pcap_open_dead(DLT_EN10MB, 65535);
	CHECK(dead != NULL);
	for (int optimize = 0; optimize <= 1; optimize++) {
		CHECK(pcap_compile(dead, &filter, "ip and udp dst port 53",
		    optimize, PCAP_NETMASK_UNKNOWN) == 0);
		CHECK(pcap_offline_filter(&filter, &header, packet) != 0);
		packet[37] = 54;
		CHECK(pcap_offline_filter(&filter, &header, packet) == 0);
		packet[37] = 53;
		header.caplen = 10;
		CHECK(pcap_offline_filter(&filter, &header, packet) == 0);
		header.caplen = sizeof(packet);
		pcap_freecode(&filter);
	}
	CHECK(pcap_compile(dead, &filter, "udp and (", 1,
	    PCAP_NETMASK_UNKNOWN) == -1);
	CHECK(strlen(pcap_geterr(dead)) != 0);

	file = tmpfile();
	CHECK(file != NULL);
	dumper = pcap_dump_fopen(dead, file);
	CHECK(dumper != NULL);
	pcap_dump((unsigned char *)dumper, &header, packet);
	CHECK(pcap_dump_flush(dumper) == 0);
	/* The dumper owns file. Read an independent copy to avoid double close. */
	FILE *copy = tmpfile();
	CHECK(copy != NULL);
	rewind(file);
	for (int c; (c = fgetc(file)) != EOF; )
		CHECK(fputc(c, copy) != EOF);
	CHECK(!ferror(file));
	pcap_dump_close(dumper);
	rewind(copy);
	reader = pcap_fopen_offline(copy, errbuf);
	CHECK(reader != NULL);
	CHECK(pcap_datalink(reader) == DLT_EN10MB);
	CHECK(pcap_snapshot(reader) == 65535);
	CHECK(pcap_next_ex(reader, &read_header, &read_packet) == 1);
	CHECK(read_header->caplen == sizeof(packet));
	CHECK(read_header->len == sizeof(packet));
	CHECK(read_header->ts.tv_sec == 123 && read_header->ts.tv_usec == 456);
	CHECK(memcmp(read_packet, packet, sizeof(packet)) == 0);
	CHECK(pcap_next_ex(reader, &read_header, &read_packet) == -2);
	pcap_close(reader);
	pcap_close(dead);
	puts("offline filter and savefile checks passed");
	return 0;
}
