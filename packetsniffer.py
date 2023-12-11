import scapy.all as scapy

def sniff_packets(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except KeyboardInterrupt:
        print("\n[*] Sniffing interrupted. Exiting.")

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"[*] IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"    [+] TCP Segment: {src_port} -> {dst_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"    [+] UDP Segment: {src_port} -> {dst_port}")

        elif packet.haslayer(scapy.ICMP):
            print("    [+] ICMP Packet")

if __name__ == "__main__":
    interface_choice = input("Enter the network interface (e.g., eth0): ")
    sniff_packets(interface_choice)
