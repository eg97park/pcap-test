#include <pcap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

#pragma pack(1)	// Disable C Stuct PADDING. https://www.geeksforgeeks.org/how-to-avoid-structure-padding-in-c/
const uint8_t MAX_PAYLOAD_PRINT_SIZE = 10;
const uint8_t IP_PROTO_TCP = 0x06;
const uint16_t ETH_TYPE_IPV4 = 0x0800;

struct MY_ETH{
	uint8_t DST_MAC_ADDR[6];
	uint8_t SRC_MAC_ADDR[6];
	uint16_t TYPE;
};


struct MY_IPV4{
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


struct MY_PACKET_HEADER_IPV4_TCP{
	struct MY_ETH ETH;
	struct MY_IPV4 IPV4;
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
		struct MY_PACKET_HEADER_IPV4_TCP pakcet_hdr;
		
		// force do memcpy.
		memcpy(&(pakcet_hdr), packet, header->caplen);

		// print only IPv4 pacekts.
		if (ntohs(pakcet_hdr.ETH.TYPE) != ETH_TYPE_IPV4){
			continue;
		}

		// print only TCP pacekts.
		if (pakcet_hdr.IPV4.PROTOCOL != IP_PROTO_TCP){
			continue;
		}

		// print source mac address.
		printf("SRC_MAC_ADDR: ");
		for (size_t _ = 0; _ < sizeof(pakcet_hdr.ETH.SRC_MAC_ADDR); _++){
			printf("%02x", pakcet_hdr.ETH.SRC_MAC_ADDR[_]);
			if (_ != sizeof(pakcet_hdr.ETH.SRC_MAC_ADDR) - 1){
				printf(":");
			}
		}
		printf("\n");

		// print destination mac address.
		printf("DST_MAC_ADDR: ");
		for (size_t _ = 0; _ < sizeof(pakcet_hdr.ETH.DST_MAC_ADDR); _++){
			printf("%02x", pakcet_hdr.ETH.DST_MAC_ADDR[_]);
			if (_ != sizeof(pakcet_hdr.ETH.DST_MAC_ADDR) - 1){
				printf(":");
			}
		}
		printf("\n");

		// print source ip address.
		uint32_t SRC_IP_ADDR = ntohl(pakcet_hdr.IPV4.SRC_IP_ADDR);
		printf("SRC_IP_ADDR: ");
		printf("%d.%d.%d.%d\n", (uint8_t)(SRC_IP_ADDR >> 24), (uint8_t)(SRC_IP_ADDR >> 16), (uint8_t)(SRC_IP_ADDR >> 8), (uint8_t)(SRC_IP_ADDR));

		// print destination ip address.
		uint32_t DST_IP_ADDR = ntohl(pakcet_hdr.IPV4.DST_IP_ADDR);
		printf("DST_IP_ADDR: ");
		printf("%d.%d.%d.%d\n", (uint8_t)(DST_IP_ADDR >> 24), (uint8_t)(DST_IP_ADDR >> 16), (uint8_t)(DST_IP_ADDR >> 8), (uint8_t)(DST_IP_ADDR));
		
		// print source port number.
		printf("SRC_PORT: %d\n", ntohs(pakcet_hdr.TCP.SRC_PORT));

		// print destination port number.
		printf("DST_PORT: %d\n", ntohs(pakcet_hdr.TCP.DST_PORT));

		// calculate tcp data length to print tcp payload.
		uint16_t ETH_HEADER_LENGTH = 14;
		uint16_t IP_HEADER_LENGTH = pakcet_hdr.IPV4.IHL * 4;
		uint16_t IP_TOTAL_LENGTH = ntohs(pakcet_hdr.IPV4.TOTAL_LEN);
		uint16_t TCP_HEADER_LENGTH = pakcet_hdr.TCP.DATA_OFFSET * 4;
		uint16_t TCP_DATA_LENGTH = IP_TOTAL_LENGTH - (IP_HEADER_LENGTH + TCP_HEADER_LENGTH);

		if (TCP_DATA_LENGTH <= 0){
			// no payload.
			printf("PAYLOAD: NO DATA\n");
		}
		else{
			// payload found. calculate payload length.
			size_t PAYLOAD_LENGTH = ETH_HEADER_LENGTH + IP_HEADER_LENGTH + TCP_HEADER_LENGTH;
			
			printf("PAYLOAD: ");
			if (PAYLOAD_LENGTH < MAX_PAYLOAD_PRINT_SIZE){
				for (size_t _ = 0; _ < PAYLOAD_LENGTH; _++){
					printf("%02x ", packet[PAYLOAD_LENGTH + _]);
				}
			}
			else{
				for (size_t _ = 0; _ < MAX_PAYLOAD_PRINT_SIZE; _++){
					printf("%02x ", packet[PAYLOAD_LENGTH + _]);
				}
			}
			printf("\n");
		}
		printf("--------------------------------------\n");
	}
	pcap_close(pcap);
}