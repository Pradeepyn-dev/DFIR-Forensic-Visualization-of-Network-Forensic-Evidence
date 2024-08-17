import pyshark

def print_packet_ip_mappings(pcap_file):
    # Read the PCAP file
    cap = pyshark.FileCapture(pcap_file)
    index = srclist = dstlist = proto = ""
    
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
            index = index + str(i+1) + "\n"
            srclist = srclist + src + "\n"
            dstlist = dstlist + dst + "\n"
            proto = proto + protocol + "\n"
            # string = string + (f"Packet {i + 1}:\t Source: {src}\t\t Destination: {dst}\t\t Protocol: {protocol}\n")
        except AttributeError:
            pass
    return index, srclist, dstlist, proto

def packet_details(pcap_file, packet_index):
    # Read the PCAP file
    cap = pyshark.FileCapture(pcap_file)
    
    # Iterate over packets to find the specified packet
    for i, packet in enumerate(cap):
        if i+1 == packet_index:
            # Return detailed information about the packet
            return str(packet)

pcap_file = "example.pcap"
# print_packet_ip_mappings(pcap_file)

packet_index = 1
packet_info = packet_details(pcap_file, packet_index)
# print("\nPacket details:")
print(packet_info)
