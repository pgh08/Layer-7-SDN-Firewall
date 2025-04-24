from scapy.all import *

# Dictionary to store the state of each TCP connection
connection_state = {}

def handle_packet(packet):
    if TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport

        # Check if it's a new connection
        if (src_ip, sport, dst_ip, dport) not in connection_state:
            connection_state[(src_ip, sport, dst_ip, dport)] = "SYN"

        # Check if it's a SYN-ACK response
        elif connection_state[(dst_ip, dport, src_ip, sport)] == "SYN" and packet[TCP].flags == 0x12:
            connection_state[(dst_ip, dport, src_ip, sport)] = "ESTABLISHED"

        # Check if it's a FIN-ACK packet
        elif connection_state[(src_ip, sport, dst_ip, dport)] == "ESTABLISHED" and packet[TCP].flags == 0x11:
            connection_state[(src_ip, sport, dst_ip, dport)] = "FIN_WAIT"

        # Check if it's a FIN-ACK response
        elif connection_state[(dst_ip, dport, src_ip, sport)] == "FIN_WAIT" and packet[TCP].flags == 0x11:
            connection_state[(dst_ip, dport, src_ip, sport)] = "CLOSED"

        # Check if it's a RST packet
        elif packet[TCP].flags == 0x14:
            connection_state[(src_ip, sport, dst_ip, dport)] = "CLOSED"
            connection_state[(dst_ip, dport, src_ip, sport)] = "CLOSED"

        print(f"Connection state: {connection_state}")

# Sniff packets and call handle_packet for each packet
sniff(prn=handle_packet, filter="tcp", store=0)
