#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void printEther(const u_char* packet){
    printf("=============Ethernet Header=============\n");
    printf("dst >> %x:%x:%x:%x:%x:%x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("src >> %x:%x:%x:%x:%x:%x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
}

void printIP(const u_char* packet){
    printf("=============IP Header=============\n");
    printf("dst >> %u.%u.%u.%u\n", packet[26], packet[27], packet[28], packet[29]);
    printf("src >> %u.%u.%u.%u\n", packet[30], packet[31], packet[32], packet[33]);
}

void printTCP(const u_char* packet){
    uint8_t srcPort[2] = {packet[34], packet[35]};
    uint8_t dstPort[2] = {packet[36], packet[37]};
    uint16_t* p = reinterpret_cast<uint16_t*>(srcPort);
    uint16_t n = ntohs(*p);
    uint16_t* q = reinterpret_cast<uint16_t*>(dstPort);
    uint16_t m = ntohs(*q);
    printf("=============TCP Port=============\n");
    printf("src port >> %u\n", n);
    printf("dst port >> %u\n", m);
}

void printPayload(const u_char* packet){
    printf("=============TCP Payload=============\n");
    printf("payload >> %x %x %x %x %x %x %x %x\n\n\n", packet[54], packet[55], packet[56], packet[57], packet[58], packet[59], packet[60], packet[61]);
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
        const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        }
        printEther(packet);
        printIP(packet);
        printTCP(packet);
        printPayload(packet);
        // printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
