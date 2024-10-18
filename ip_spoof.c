#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

unsigned short in_cksum (unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum) adds sequential 16 bit
     * words to it, and at the end, folds back all the carry bits from the
     * top 16 bits into the lower 16 bits
     */

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *) (&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                    // add carry
    return (unsigned short) (~sum);
}



uint16_t calc_checksum(void *buff, size_t len) {
    uint16_t *buf = (uint16_t*)buff;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}




uint16_t calculate_checksum(unsigned char* buffer, int bytes)
{
    uint32_t checksum = 0;
    unsigned char* end = buffer + bytes;

    // odd bytes add last byte and reset end
    if (bytes % 2 == 1) {
        end = buffer + bytes - 1;
        checksum += (*end) << 8;
    }

    // add words of two bytes, one by one
    while (buffer < end) {
        checksum += buffer[0] << 8;
        checksum += buffer[1];
        buffer += 2;
    }

    // add carry if any
    uint32_t carray = checksum >> 16;
    while (carray) {
        checksum = (checksum & 0xffff) + carray;
        carray = checksum >> 16;
    }

    // negate it
    checksum = ~checksum;

    return checksum & 0xffff;
}

unsigned short cksum(void *buf, int len) {
    unsigned short *wordPtr = (unsigned short*)buf;
    long sum = 0;

    while (len > 1) {
        sum += *wordPtr++;
        if (sum & 0x80000000)   // if high order bit set, fold
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    // Add left-over byte, if any
    if (len > 0)
        sum += * (unsigned char *) wordPtr; 

    // Fold sum to 16 bits: add carrier to result
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // One's complement and truncate to 16 bits
    return (unsigned short)~sum;
}

/*
     unsigned short cksum(unsigned short* ip, int len){
       long sum = 0;  

       while(len > 1){
         sum += *(ip)++;
         if(sum & 0x80000000)
           sum = (sum & 0xFFFF) + (sum >> 16);
         len -= 2;
       }

       if(len)       
         sum += (unsigned short) *(unsigned char *)ip;

       while(sum>>16)
         sum = (sum & 0xFFFF) + (sum >> 16);

       return ~sum;
     }

*/

void print_ip_address(const char* label, uint32_t ip_addr) {
    struct in_addr ip;
    ip.s_addr = ip_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
    printf("%s: %s\n", label, ip_str);
}

void print_packet(const u_char* packet, size_t length) {
    printf("Packet Contents (Hexadecimal):\n");
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", packet[i]);
        if ((i + 1) % 16 == 0) {  // Print a new line every 16 bytes
            printf("\n");
        }
    }
    printf("\n");
}

void send_raw_ip_packet(iphdr* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;
    
    print_ip_address("Source IP in response packet", ip->saddr);
    print_ip_address("Destination IP response packet", ip->daddr);
    
    // Create a raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Destination info
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = ip->daddr;

    // Send the packet out
    printf("Sending spoofed IP packet...\n");
    if (sendto(sock, ip, ntohs(ip->tot_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("PACKET NOT SENT");
    } else {
        printf("Packet sent successfully\n");
    }
    close(sock);
}

void send_icmp_reply(in_addr saddr, in_addr daddr, uint16_t id, uint16_t sequence, char* payload, uint32_t icmp_payload_len) {
	char buffer[1024] = {0};
	// ide says i can replace memset with 0
	// initialization for buffer.
	// memset(buffer, 0, 1024);
	iphdr* ip = (iphdr*)buffer;
	ip->version = 4;
	ip->ihl = 5;
	ip->ttl = 99;
	ip->saddr = saddr.s_addr;
	ip->daddr = daddr.s_addr;
	ip->protocol = IPPROTO_ICMP;
	ip->check = 0; 

	// ip->tos can be left as 0 for precedent.
	icmphdr* icmp = (icmphdr*)(buffer + (ip->ihl * 4));
	icmp->type = ICMP_ECHOREPLY;
	icmp->code = 0;
	icmp->un.echo.id = id;
	icmp->un.echo.sequence = sequence;
	int packet_length = sizeof(struct icmphdr) + icmp_payload_len;
	//icmp->checksum = compute_icmp_checksum(icmp, packet_length);
	//icmp->checksum = compute_icmp_checksum((unsigned short*) icmp, sizeof(struct icmphdr) + icmp_payload_len);
	icmp->checksum = 0;
	// copy payload into buffer.
	// important to have payload there before calculating checksum
	memcpy(buffer + ip->ihl * 4 + sizeof(icmphdr), payload, icmp_payload_len);
	icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + icmp_payload_len); 

	ip->tot_len = htons(ip->ihl * 4);
	send_raw_ip_packet(ip);
	ip->tot_len = htons(ip->ihl * 4 + sizeof(struct icmphdr) + icmp_payload_len);

    	print_packet((u_char*) buffer, ntohs(ip->tot_len));
	send_raw_ip_packet(ip);
}

void print_ip(struct in_addr ip) {
	unsigned char a, b, c, d;
	int ipNum = ntohl(ip.s_addr);
	a = ipNum >> (3 * 8);
	b = (ipNum & (0xf << 2 * 8)) >> (2 * 8);
	c = (ipNum & (0xf << 1 * 8 )) >> (1 * 8);
	d = (ipNum & (0xf << 0 * 8 )) >> (0 * 8);
	printf("%d.%d.%d.%d\n", a, b, c, d);

}
void got_packet(u_char *args, const struct pcap_pkthdr *header,
const u_char *packet)
{
	printf("Got a packet-----------------\n");
	int ip_size = sizeof(struct ip);
	int icmp_size = sizeof(struct icmphdr);
	const struct ether_header *ethernet = (struct ether_header*) packet;
	const struct ip *ip = (struct ip*)(packet + sizeof(struct ether_header));
	print_ip(ip->ip_src);
	print_ip(ip->ip_dst);

	struct icmphdr *icmp = (struct icmphdr*) ((u_char *)ip + ip->ip_hl * 4);
	// remember that adding 1 to a pointer type means adding 1 * that type length
	// NOT one byte
	char *payload = (char*)(icmp + 1);
	// total packet length - header length - icmp length
	int payload_length = ntohs(ip->ip_len) - (ip->ip_hl * 4 + sizeof(icmphdr));
	printf("Payload length = %d\n", payload_length);

	for (int i = 0; i < payload_length; i++) {
		char c = payload[i];
		if (c >= 32 && c <= 126) {
			putchar(c);
		} else {
			putchar('.');
		}
	}
	putchar('\n');
	printf("Starting the sender function\n");
	send_icmp_reply(ip->ip_dst, ip->ip_src, icmp->un.echo.id, icmp->un.echo.sequence, payload, payload_length);
	printf("Reply worked?!\n");
}
int main()
{
printf("Size of ip %d, and sizeof iphdr %d\n", sizeof(struct ip), sizeof(struct iphdr));
printf("Size of ICMP  %d\n", sizeof(struct icmphdr));
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "icmp and src host 10.9.0.6";
//char filter_exp[] = "tcp and (src portrange 1-8000 or dst portrange 10-8000)";

//char filter_exp[] = "tcp and dst host 10.9.0.5";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name eth3.
// Students need to change "eth3" to the name found on their own
// machines (using ifconfig). The interface to the 10.9.0.0/24
// network has a prefix "br-" (if the container setup is used).
handle = pcap_open_live("br-0d031b6f5c71", BUFSIZ, 1, 4000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
if (pcap_setfilter(handle, &fp) !=0) {
	pcap_perror(handle, "Error:");
exit(EXIT_FAILURE);
}
// Step 3: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); //Close the handle
return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap

