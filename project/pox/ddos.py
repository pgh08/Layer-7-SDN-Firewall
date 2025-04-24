from pox.core import core
import pox.openflow.libopenflow_01 as of

# Dictionary to keep track of packet counts for each host
packet_count = {}

# Maximum allowed packet count per second per host
MAX_PACKETS_PER_SEC = 10

def _handle_PacketIn(event):
    packet = event.parsed
    if packet.type != packet.IP_TYPE:
        return

    ip_packet = packet.payload
    src_ip = ip_packet.srcip

    if src_ip not in packet_count:
        packet_count[src_ip] = 0

    packet_count[src_ip] += 1

    if packet_count[src_ip] > MAX_PACKETS_PER_SEC:
        # DDoS attack detected
        print(f"DDoS attack detected from {src_ip}, blocking traffic...")
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)
        return

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    print("DDoS Mitigation is running...")

