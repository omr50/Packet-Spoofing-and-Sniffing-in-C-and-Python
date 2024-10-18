from scapy.all import *

def print_pkt(pkt):
    print("Got Packet")
    pkt.show()

# -- capture only icmp packets
#pkr = sniff(iface='br-0d031b6f5c71', filter='icmp', prn=print_pkt)
# -- Capture any TCP packets that comes from a particular IP and with
# -- a desintation port of 8000
#pkr = sniff(iface='br-0d031b6f5c71', filter='host 10.9.0.6 and tcp dst port 8000', prn=print_pkt)
# -- capture packets that come from or go to a particular subnet. You can pick 
# -- any subnet except the one your vm is attached to.
pkr = sniff(iface='br-0d031b6f5c71', filter='src net 142.251.40/24 or dst net 142.251.40/24', prn=print_pkt)

