#include <pcap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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
	uint16_t TOTAL_LEN;
	uint16_t ID;
	uint16_t FLAG_FRAGOFFSET;
	uint8_t TTL;
	uint8_t PROTOCOL;
	uint16_t HDR_CHKSUM;
	uint32_t SRC_IP_ADDR;
	uint32_t DST_IP_ADDR;
};


struct MY_TCP{
	uint16_t SRC_PORT;
	uint16_t DST_PORT;
	uint32_t SEQ_NUM;
	uint32_t ACK_NUM;
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char FLAGS_RESERVED_NS:4;
	u_char DATA_OFFSET:4;
#else
	u_char DATA_OFFSET:4;
	u_char FLAGS:4;
#endif
	uint8_t FLAGS_ETC:4;
	uint16_t WIN_SIZE;
	uint16_t CHKSUM;
	uint16_t URG_PTR;
};


struct MY_PACKET_HDR{
	struct MY_ETH ETH;
	struct MY_IP IP;
	struct MY_TCP TCP;
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

		/*
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
		*/

		// IP
		/*
		printf("IP.VER: %02x \n", pakcet_hdr.IP.VER);
		printf("IP.IHL: %02x \n", pakcet_hdr.IP.IHL);
		printf("IP.DSCP_ECN: %02x \n", pakcet_hdr.IP.DSCP_ECN);
		printf("IP.TOTAL_LENGTH: %04x \n", ntohs(pakcet_hdr.IP.TOTAL_LEN));
		printf("IP.IDENTIFICATION: %04x \n", ntohs(pakcet_hdr.IP.ID));
		printf("IP.FLAGS_FRAGOFFSET: %04x \n", ntohs(pakcet_hdr.IP.FLAG_FRAGOFFSET));
		printf("IP.TTL: %02x \n", pakcet_hdr.IP.TTL);
		printf("IP.PROTOCOL: %02x \n", pakcet_hdr.IP.PROTOCOL);
		printf("IP.HEADER_CHKSUM: %04x \n", ntohs(pakcet_hdr.IP.HDR_CHKSUM));
		*/
		printf("IP.SRC_IP_ADDR: %08x \n", ntohl(pakcet_hdr.IP.SRC_IP_ADDR));
		printf("IP.DST_IP_ADDR: %08x \n", ntohl(pakcet_hdr.IP.DST_IP_ADDR));
		printf("TCP.SRC_PORT: %04x \n", ntohs(pakcet_hdr.TCP.SRC_PORT));
		printf("TCP.DST_PORT: %04x \n", ntohs(pakcet_hdr.TCP.DST_PORT));
		
		/*
		printf("TCP.SEQ_NUM: %08x \n", ntohl(pakcet_hdr.TCP.SEQ_NUM));
		printf("TCP.ACK_NUM: %08x \n", ntohl(pakcet_hdr.TCP.ACK_NUM));
		printf("TCP.DATA_OFFSET: %02x \n", pakcet_hdr.TCP.DATA_OFFSET);
		printf("TCP.FLAGS_RESERVED_NS: %02x \n", pakcet_hdr.TCP.FLAGS_RESERVED_NS);
		printf("TCP.FLAGS_ETC: %02x \n", pakcet_hdr.TCP.FLAGS_ETC);
		printf("TCP.WIN_SIZE: %04x \n", ntohs(pakcet_hdr.TCP.WIN_SIZE));
		printf("TCP.CHKSUM: %04x \n", ntohs(pakcet_hdr.TCP.CHKSUM));
		printf("TCP.URG_PTR: %04x \n", ntohs(pakcet_hdr.TCP.URG_PTR));
		*/

		uint16_t ETH_HEADER_LENGTH = 14;
		uint16_t IP_HEADER_LENGTH = pakcet_hdr.IP.IHL * 4;
		uint16_t IP_TOTAL_LENGTH = ntohs(pakcet_hdr.IP.TOTAL_LEN);
		uint16_t TCP_HEADER_LENGTH = pakcet_hdr.TCP.DATA_OFFSET * 4;
		uint16_t TCP_DATA_LENGTH = IP_TOTAL_LENGTH - (IP_HEADER_LENGTH + TCP_HEADER_LENGTH);
		printf("IP_HEADER_LENGTH= %d\n", IP_HEADER_LENGTH);
		printf("IP_TOTAL_LENGTH= %d\n", IP_TOTAL_LENGTH);
		printf("TCP_HEADER_LENGTH= %d\n", TCP_HEADER_LENGTH);
		printf("TCP_DATA_LENGTH= %d\n", TCP_DATA_LENGTH);

		if (TCP_DATA_LENGTH <= 0){
			printf("NO DATA\n");
		}
		else{
			printf("PAYLOAD: ");
			size_t PAYLOAD_OFFSET = ETH_HEADER_LENGTH + IP_HEADER_LENGTH + TCP_HEADER_LENGTH;
			printf("PAYLOAD_OFFSET=%ld\tTCP_DATA_LENGTH=%d\n", PAYLOAD_OFFSET, TCP_DATA_LENGTH);
			for (size_t _ = 0; _ < TCP_DATA_LENGTH; _++){
				printf("%02x ", packet[PAYLOAD_OFFSET + _]);
			}
			printf("\n");
		}
		
		printf("%u bytes captured\n\n", header->caplen);
	}

	pcap_close(pcap);
}