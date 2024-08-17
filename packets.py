import pyshark
from scapy.all import *

def print_packet_ip_mappings(pcap_file):
    # Read the PCAP file
    cap = pyshark.FileCapture(pcap_file)
    index = list()
    srclist = list()
    dstlist = list()
    proto = list()
    
    # Extract and print source and destination IP addresses from each packet in the PCAP file
    for i, packet in enumerate(cap):
        try:
            if 'ip' in packet:
                src = packet.ip.src
                dst = packet.ip.dst
            elif 'eth' in packet:
                src = packet.eth.src
                dst = packet.eth.dst
            else:
                src = "Unknown"
                dst = "Unknown"
            
            protocol = packet.layers[-1].layer_name
            if(protocol == 'DATA'):
                for j in range(1, len(packet.layers)):
                    if(protocol!="DATA"):
                        break
                    else:
                        protocol = packet.layers[-j].layer_name
            index.append(i+1)
            srclist.append(src)
            dstlist.append(dst)
            proto.append(protocol)
        except AttributeError:
            pass
    return index, srclist, dstlist, proto

def packet_details(pcap_file, packet_index):
    # Read the PCAP file
    cap = rdpcap(pcap_file)
    
    # Iterate over packets to find the specified packet
    for i, packet in enumerate(cap):
        if i+1 == packet_index:
            k = "Selected packet index: " + str(packet_index) + "\n\n"
            k = k + packet.show(dump = True)
            return k
        
# packet_details("example.pcap", 1)