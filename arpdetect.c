/*
 * Watches ARP packets in order to detect new machines on the local network.
 * Must be run as root.
 * 
 * Based on example code from http://www.tcpdump.org/sniffex.c
 *
 * TODO: Only intercepting arp packets is finished. Need to determine when a new address has appeared.
 */

#include <signal.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET 14

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN]; 
    u_short ether_type;
};

struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}arphdr_t; 
 
pcap_t *handle;


void packet_handler();
void intHandler(int sig);

int main() {

    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    const u_char *pkt;
    struct pcap_pkthdr header;

    signal(SIGINT, intHandler);
         
    dev = pcap_lookupdev(errbuf);

    if(dev == NULL) {
        fprintf(stderr, "Could not find default device: %s\n", errbuf);
        return(2);
    }

    printf("Device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
    }

   
    pcap_loop(handle, -1, &packet_handler, NULL);

    return 0;
}

void get_macaddr_str(char * buf, const u_char * src) {
    static const char * template = "0123456789ABCDEF";
    int i;

    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        buf[3*i] = template[(src[i] & 0xF0) >> 4];
        buf[3*i+1] = template[(src[i] & 0x0F)];
        buf[3*i+2] = ':';
    }
    buf[17] = '\0';
}

int is_mac_broadcast(const u_char * src) {
    int i;

    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        if(src[i] != 0) {
            return 0;
        }
    }

    return 1;
}

void iptostr(char * buf, const u_char * ipstr) {
    sprintf(buf, "%d.%d.%d.%d", ipstr[0], ipstr[1], ipstr[2], ipstr[3]);
}

void arp_handler(u_char * args, const struct pcap_pkthdr * header, const u_char *pkt) {
    char ipstrsrc[16];
    char ipstrdst[16];

    arphdr_t * arphdr;

    arphdr = (arphdr_t *) (pkt + SIZE_ETHERNET);

    if(arphdr->ptype = 0x0800) {
        char dst_macaddrstr[ETHER_ADDR_LEN * 2 + 5 + 1];
        char src_macaddrstr[ETHER_ADDR_LEN * 2 + 5 + 1];
        
        if(ntohs(arphdr->oper) == ARP_REQUEST) {
            printf("ARP REQ ");
        } else {
            printf("ARP REP ");
        }

        if(is_mac_broadcast(arphdr->tha)) {
            printf("<<< BROADCAST >>> ");
        }
        
        get_macaddr_str(src_macaddrstr, arphdr->sha);
        get_macaddr_str(dst_macaddrstr, arphdr->tha);
        iptostr(ipstrsrc, arphdr->spa);
        iptostr(ipstrdst, arphdr->tpa);
        printf("%s (%s) -> %s (%s)\n", src_macaddrstr, ipstrsrc, dst_macaddrstr, ipstrdst);
    } 
}

void packet_handler(u_char * args, const struct pcap_pkthdr * header, const u_char *pkt) {
    char dst_macaddrstr[ETHER_ADDR_LEN * 2 + 5 + 1];
    char src_macaddrstr[ETHER_ADDR_LEN * 2 + 5 + 1];
    const struct sniff_ethernet *eth;
    const struct sniff_ip *ip;
    int size_ip = 0;

    eth = (struct sniff_ethernet *) pkt;
   
    get_macaddr_str(dst_macaddrstr, eth->ether_dhost);
    get_macaddr_str(src_macaddrstr, eth->ether_shost);

    //printf("ETH:  %s -> %s\n", src_macaddrstr, dst_macaddrstr);

    ip = (struct sniff_ip *) (pkt + SIZE_ETHERNET);    

    size_ip = IP_HL(ip) * 4;
    if(size_ip < 20) {
        arp_handler(args, header, pkt);
        return;
    }    

    //printf("IP: %s -> ", inet_ntoa(ip->ip_src));
    //printf("%s", inet_ntoa(ip->ip_dst));

    switch(ip->ip_p) {
        case IPPROTO_TCP:
            //printf(" (TCP)\n");
            break;
        case IPPROTO_UDP:
            //printf(" (UDP)\n");
            return;
        case IPPROTO_ICMP:
            //printf(" (ICMP)\n");
            return;
        case IPPROTO_IP:
            //printf(" (IP)\n");
            return;
        default:
            //printf(" (unknown)\n");
            return;
    
    }
}

void intHandler(int sig) {
    signal(sig, SIG_IGN);

    printf("Exiting.\n");
    pcap_close(handle);
}


