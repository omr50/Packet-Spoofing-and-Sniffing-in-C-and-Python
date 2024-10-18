#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/

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
	int tcp_size = sizeof(struct tcphdr);
	const struct ether_header *ethernet = (struct ether_header*) packet;
	const struct ip *ip = (struct ip*)(packet + sizeof(struct ether_header));
	print_ip(ip->ip_src);
	print_ip(ip->ip_dst);
	printf("IP PACKET pointer %p compared with %p\n", ip, (packet + sizeof(struct ether_header))); 
    const struct tcphdr *tcp2 = (struct tcphdr*) (packet + sizeof(struct ether_header) + ip->ip_hl * 4);
	struct tcphdr *tcp = (struct tcphdr*) ((u_char *)ip + ip->ip_hl * 4);
	printf("TCP PACKET pointer %p compared with %p\n",tcp2, tcp); 
	const char *payload = (const char*)((u_char*)tcp + tcp->doff * 4);
	int payload_length = ntohs(ip->ip_len) - (ip->ip_hl * 4 + tcp->doff * 4); 
	
	for (int i = 0; i < payload_length; i++) {
		char c = payload[i];
		if (c >= 32 && c <= 126) {
			putchar(c);
		} else {
			putchar('.');
		}
	}
	putchar('\n');
}
/*
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Got a packet-----------------\n");
    const struct ether_header *ethernet = (struct ether_header*) packet;
    const struct ip *ip = (struct ip*)(packet + sizeof(struct ether_header));
    print_ip(ip->ip_src);
    print_ip(ip->ip_dst);
    const struct tcphdr *tcp = (struct tcphdr*) (packet + sizeof(struct ether_header) + ip->ip_hl * 4);
    const char *payload = (const char*)(packet + sizeof(struct ether_header) + ip->ip_hl * 4 + tcp->doff * 4);
    int payload_length = ntohs(ip->ip_len) - (ip->ip_hl * 4 + tcp->doff * 4);

    for (int i = 0; i < payload_length; i++) {
        char c = payload[i];
        if (c >= 32 && c <= 126) {
            putchar(c);
        } else {
            putchar('.');
        }
    }
    putchar('\n');
}

*/
int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
// char filter_exp[] = "icmp and src host 10.9.0.6 and dst host 10.9.0.5";
//char filter_exp[] = "tcp and (src portrange 1-8000 or dst portrange 10-8000)";

char filter_exp[] = "tcp and dst host 10.9.0.5"; 
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

