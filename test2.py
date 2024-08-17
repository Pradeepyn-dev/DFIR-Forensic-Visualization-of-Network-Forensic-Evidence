import pyshark

def extract_ip_addresses_from_pcap_yield(pcap_file):
    # Read the PCAP file
    cap = pyshark.FileCapture(pcap_file)
    
    # Extract IP addresses from each packet in the PCAP file
    for packet in cap:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            yield src_ip, dst_ip
        except AttributeError:
            pass

# Example usage
# pcap_file = "example.pcap"
# for src_ip, dst_ip in extract_ip_addresses_from_pcap_yield(pcap_file):
#     print("Source IP address:", src_ip)
#     print("Destination IP address:", dst_ip)
#     print()
