from scapy.all import *
import sys


hostname = sys.argv[1]

pkt = IP(dst=hostname, ttl=100) / ICMP()
reply = sr1(pkt, verbose=0, timeout=1)
print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
reply.show()

for i in range(1, 20):
    print("CURRENT ITERATION", i)
    pkt = IP(dst=hostname, ttl=i) / ICMP()
    # Send the packet and get a reply
    reply = sr1(pkt, verbose=0, timeout=1)
    if reply is None:
        print("No response received.")
        continue

    reply.show()
    if reply.type == 3:
        print("Done!", reply.src)
        break
    else:
        print(i, "hops away:", reply.src)

