#include <pcap.h>
#include <stdbool.h>
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <stdio.h> // for printf
#include <memory.h>
#include <string.h>

#pragma pack(1)	// Disable C Stuct PADDING. https://www.geeksforgeeks.org/how-to-avoid-structure-padding-in-c/

struct MY_ETH{
	uint8_t DST_MAC_ADDR[6];
	uint8_t SRC_MAC_ADDR[6];
	uint16_t TYPE;
};


struct MY_IP{
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char IHL:4;
	u_char VER:4;
#else
	u_char VER:4;
	u_char IHL:4;
#endif
	uint8_t DSCP_ECN;
	uint16_t TOTAL_LENGTH;
	uint16_t IDENTIFICATION;
	uint16_t FLAGS_FRAGOFFSET;
	uint8_t TTL;
	uint8_t PROTOCOL;
	uint16_t HEADER_CHKSUM;
	uint32_t SRC_IP_ADDR;
	uint32_t DST_IP_ADDR;
};


struct MY_PACKET_HDR{
	struct MY_ETH ETH;
	struct MY_IP IP;
};


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
		struct MY_PACKET_HDR pakcet_hdr;
		
		memcpy(&(pakcet_hdr), packet, header->caplen);

		// DST_MAC_ADDR
		printf("ETH.DST_MAC_ADDR: ");
		for (size_t _ = 0; _ < sizeof(pakcet_hdr.ETH.DST_MAC_ADDR); _++){
			printf("%02x ", pakcet_hdr.ETH.DST_MAC_ADDR[_]);
		}
		printf("\n");

		// SRC_MAC_ADDR
		printf("ETH.SRC_MAC_ADDR: ");
		for (size_t _ = 0; _ < sizeof(pakcet_hdr.ETH.SRC_MAC_ADDR); _++){
			printf("%02x ", pakcet_hdr.ETH.SRC_MAC_ADDR[_]);
		}
		printf("\n");

		// ETH_TYPE
		if (ntohs(pakcet_hdr.ETH.TYPE) == 0x0800){
			// IPv4
			printf("ether_type: %04x (IPv4)\n", ntohs(pakcet_hdr.ETH.TYPE));
		}
		else if (ntohs(pakcet_hdr.ETH.TYPE) == 0x86DD){
			// IPv6
			printf("ether_type: %04x (IPv6)\n", ntohs(pakcet_hdr.ETH.TYPE));
		}
		else if (ntohs(pakcet_hdr.ETH.TYPE) == 0x0806){
			// ARP
			printf("ether_type: %04x (ARP)\n", ntohs(pakcet_hdr.ETH.TYPE));
		}
		else{
			// ETC
			printf("ether_type: %04x (ETC)\n", ntohs(pakcet_hdr.ETH.TYPE));
		}

		// IP
		printf("IP.VER: %02x \n", pakcet_hdr.IP.VER);
		printf("IP.IHL: %02x \n", pakcet_hdr.IP.IHL);
		printf("IP.DSCP_ECN: %02x \n", pakcet_hdr.IP.DSCP_ECN);
		printf("IP.TOTAL_LENGTH: %04x \n", ntohs(pakcet_hdr.IP.TOTAL_LENGTH));
		printf("IP.IDENTIFICATION: %04x \n", ntohs(pakcet_hdr.IP.IDENTIFICATION));
		printf("IP.FLAGS_FRAGOFFSET: %04x \n", ntohs(pakcet_hdr.IP.FLAGS_FRAGOFFSET));
		printf("IP.TTL: %02x \n", pakcet_hdr.IP.TTL);
		printf("IP.PROTOCOL: %02x \n", pakcet_hdr.IP.PROTOCOL);
		printf("IP.HEADER_CHKSUM: %04x \n", ntohs(pakcet_hdr.IP.HEADER_CHKSUM));
		printf("IP.SRC_IP_ADDR: %08x \n", ntohl(pakcet_hdr.IP.SRC_IP_ADDR));
		printf("IP.DST_IP_ADDR: %08x \n", ntohl(pakcet_hdr.IP.DST_IP_ADDR));


		printf("%u bytes captured\n\n", header->caplen);
	}

	pcap_close(pcap);
}