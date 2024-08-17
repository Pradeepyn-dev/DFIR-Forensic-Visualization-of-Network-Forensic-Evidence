from scapy.all import *

# Read the PCAP file
scapy_cap = rdpcap('example.pcap')

# Iterate through each packet and print the source IPv6 address
for index, packet in enumerate(scapy_cap):
    if(index == 1):
        print(index)
        k = packet.show(dump = True)
        print(k)