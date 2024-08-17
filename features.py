import pyshark
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np
import pandas as pd

# Read PCAP file

def protocol_distribution(filepath):
    cap = pyshark.FileCapture(filepath)
    protocols = []
    for packet in cap:
        try:
            last_layer_protocol = packet.layers[-1].layer_name
            if last_layer_protocol == 'DATA':
                for j in range(1, len(packet.layers)):
                    if last_layer_protocol != "DATA":
                        break
                    else:
                        last_layer_protocol = packet.layers[-j].layer_name
            protocols.append(last_layer_protocol)
        except AttributeError: 
            pass

    # Count occurrences of each protocol
    protocol_counts = {}
    for protocol in protocols:
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    # Order protocols based on frequency
    sorted_protocols = sorted(protocol_counts.keys(), key=lambda x: protocol_counts[x], reverse=True)

    # Sort protocol counts based on sorted protocols
    sorted_protocol_counts = {protocol: protocol_counts[protocol] for protocol in sorted_protocols}

    # Assign colors to protocols
    num_protocols = len(sorted_protocol_counts)
    colors = cm.tab20b(np.linspace(0, 1, num_protocols))

    cap.close()

    # Plot protocol distribution as a pie chart
    return sorted_protocol_counts, sorted_protocols, colors


def traffic_volume(filepath):
    cap = pyshark.FileCapture(filepath)

    # Extract packet timestamps and lengths
    timestamps = []
    lengths = []
    prev_time = None
    for packet in cap:
        try:
            if prev_time is not None:
                time_diff = (packet.sniff_time - prev_time).total_seconds() * 1000  # Convert to milliseconds
                timestamp = timestamps[-1] + time_diff if timestamps else 0
            else:
                timestamp = 0
            length = int(packet.length)
            timestamps.append(timestamp)
            lengths.append(length)
            prev_time = packet.sniff_time
        except AttributeError:
            pass

    # Create DataFrame
    df = pd.DataFrame({'Timestamp': timestamps, 'Length': lengths})

    # Group by timestamp and calculate total length
    traffic_volume = df.groupby('Timestamp')['Length'].sum()

    cap.close()

    return traffic_volume

def top_talkers(filepath):
    cap = pyshark.FileCapture(filepath)

    # Extract source and destination IP addresses and packet lengths
    src_ips = []
    dst_ips = []
    lengths = []
    for packet in cap:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            length = int(packet.length)
            src_ips.append(src_ip)
            dst_ips.append(dst_ip)
            lengths.append(length)
        except AttributeError:
            pass

    # Create DataFrame
    df = pd.DataFrame({'Source IP': src_ips, 'Destination IP': dst_ips, 'Length': lengths})

    # Group by IP addresses and calculate total traffic
    top_talkers = df.groupby('Source IP')['Length'].sum().nlargest(10)

    cap.close()

    return top_talkers

def packet_length_distribution(filepath):
    cap = pyshark.FileCapture("example.pcap")
    packet_lengths = [int(packet.length) for packet in cap if hasattr(packet, 'length')]
    cap.close()
    return packet_lengths

def traffic_ports(filepath):
    cap = pyshark.FileCapture(filepath)

    # Extract source and destination ports for both TCP and UDP packets
    ports = []
    for packet in cap:
        try:
            if 'tcp' in packet:
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            elif 'udp' in packet:
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
            else:
                continue
            ports.append(src_port)
            ports.append(dst_port)
        except AttributeError:
            pass

    # Count occurrences of each port
    port_counts = {}
    for port in ports:
        if port in port_counts:
            port_counts[port] += 1
        else:
            port_counts[port] = 1

    # Divide ports into two groups: ports from 1 to 1024 and ports beyond 1024
    ports_low = [port for port in port_counts.keys() if port <= 1024]
    ports_high = [port for port in port_counts.keys() if port > 1024]

    # Get top 10 ports for ports_low and ports_high
    sorted_ports_low = sorted([(k, v) for k, v in port_counts.items() if k <= 1024], key=lambda x: x[1], reverse=True)[:10]
    sorted_ports_high = sorted([(k, v) for k, v in port_counts.items() if k > 1024], key=lambda x: x[1], reverse=True)[:10]

    cap.close()
    
    return port_counts, ports_low, ports_high, sorted_ports_low, sorted_ports_high