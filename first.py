import pyshark

def packet_handler(pkt):
    print(pkt)  # Print the captured packet

def capture_packets(interface_name, packet_count):
    # Start capturing packets from the specified interface
    capture = pyshark.LiveCapture(interface=interface_name)

    # Register a callback function to handle each captured packet
    capture.apply_on_packets(packet_handler, packet_count=packet_count)

# Example usage
interface_name = "Wi-Fi"  # Specify the interface name you want to capture packets from
packet_count = 10  # Specify the number of packets to capture

capture_packets(interface_name, packet_count)