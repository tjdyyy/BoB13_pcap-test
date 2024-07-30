#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h> // ip 주소 변환 위한 함수 포함
// #include <netinet/ip.h> // ip 헤더 구조체 정의
// #include <netinet/tcp.h> // tcp 헤더 구조체 정의
//#include <netinet/ether.h> // ethernet 헤더 구조체 정의

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];   /* destination ethernet address */
    u_int8_t  ether_shost[6];   /* source ethernet address */
    u_int16_t ether_type;       /* protocol */ 
};


// /*
//  * Source Route Entries (SRE)
//  * This is used for GRE as the Routing field is a list of SREs - RFC 1701
//  * Base header size: 4 bytes
//  */
// struct libnet_gre_sre_hdr
// {
//     u_int16_t af;  /* address familly */
//     u_int8_t sre_offset;
//     u_int8_t sre_length;
//     u_int8_t *routing;
// };


/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,      /* header length */
             ip_v:4;         /* version */

    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;         /* fragment offset field */

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};



/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */

    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */

    u_int8_t  th_flags;       /* control flags */

    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};


// 프로그램 사용법 출력
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

// 구조체 - 네트워크 인터페이스 이름 저장
typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

// 네트워크 인터페이스 이름 -> param 구조체에 저장. (명령행 인자 파싱)
bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) { // 인자 개수 다르면
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

// MAC -> 16진수 출력
void print_mac(const u_char *mac) {
    for(int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

// payload 최대 20byte 16진수 출력
void print_payload(const u_char *payload, int len) {
    int print_len = len < 20 ? len : 20;
    for (int i = 0; i < print_len; i++) {
        printf("%02x ", payload[i]);
    }
    if (len > 20) printf("...");
    printf("\n");
}

int main(int argc, char* argv[]) {
    // 명령행 인자 파싱
    if (!parse(&param, argc, argv))
        return -1;

    // 네트워크 인터페이스 열고 패킷 캡처 시작
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    // 패킷 캡처 반복문
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        // 다음 패킷 가져오기
        int res = pcap_next_ex(pcap, &header, &packet); 
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // Ethernet 헤더 파싱 -> MAC 주소 출력
        struct libnet_ethernet_hdr *eth_header = (struct libnet_ethernet_hdr *) packet;
        printf("Ethernet Header\n");
        printf("Src MAC: ");
        print_mac(eth_header->ether_shost);
        printf("\nDst MAC: ");
        print_mac(eth_header->ether_dhost);
        printf("\n");

        // IP 헤더 파싱
        if (ntohs(eth_header->ether_type) == 0X0800) {
            // ethernet 헤더 타입이 ip인 경우 -> ip 헤더 파싱 -> 출력
            struct libnet_ipv4_hdr *ip_header = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
            printf("IP Header\n");
            printf("Src IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

            // TCP 헤더 파싱
            if (ip_header->ip_p == 6) {
                // ip 헤더 타입이 tcp인 경우 -> tcp 헤더 파싱 -> 포트번호 출력
                struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header->ip_hl * 4);
                printf("TCP Header\n");
                printf("Src Port: %d\n", ntohs(tcp_header->th_sport));
                printf("Dst Port: %d\n", ntohs(tcp_header->th_dport));

                // Payload 출력 - 최대 20바이트, 16진수
                const u_char *payload = packet + sizeof(struct libnet_ethernet_hdr) + ip_header->ip_hl * 4 + tcp_header->th_off * 4;
                int payload_len = header->caplen - (payload - packet);
                printf("Payload (first 20 bytes): ");
                print_payload(payload, payload_len);
	    }
        }

        printf("\n");
    }

    pcap_close(pcap);
    return 0;
}
