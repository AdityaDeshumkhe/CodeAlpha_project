from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}")

        # Check for TCP packets
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

        # Check for UDP packets
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Packet: Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

        # Check for ICMP packets
        elif ICMP in packet:
            print("ICMP Packet")

def start_sniffer(interface=None):
    print("Starting the network sniffer...")
    # Start sniffing packets
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # You can specify the network interface to sniff on, e.g., 'eth0', 'wlan0', etc.
    # If you want to sniff on all interfaces, you can set it to None.
    start_sniffer(interface=None)