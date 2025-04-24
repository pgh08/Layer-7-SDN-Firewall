from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.udp import udp

# Dictionary to keep track of packet counts for each host
packet_count = {}

# Maximum allowed packet count per second per host
MAX_PACKETS_PER_SEC = 200000

# Dictionary to store signatures of known malicious traffic patterns
signatures =[
    "malicious_pattern1",
    "malicious_pattern2"
    # Add more signatures as needed
]

def _handle_PacketIn(event):
    packet = event.parsed
    if packet.type != packet.IP_TYPE:
        return

    ip_packet = packet.payload
    src_ip = ip_packet.srcip
    if isinstance(ip_packet.payload ,udp):
    	udp_packet = ip_packet.payload
    	message = udp_packet.payload
    	intrusion_signature = str(message)
    	s = str(intrusion_signature.split())
    	for signature in signatures:
    		x = str(signature)
    		if x in s:
        		print(f"Intrusion detected: {intrusion_signature}, blocking traffic...")
        		"""msg = of.ofp_packet_out()
        		msg.data = event.ofp
        		msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
        		event.connection.send(msg)"""
        		return
    	
    	
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

    # Add UDP blocking rule
    """if ip_packet.protocol == ip_packet.UDP_PROTOCOL:
        print(f"UDP packet detected from {src_ip}, blocking UDP traffic...")
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
        event.connection.send(msg)"""

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    print("DDoS Mitigation with Intrusion Detection Firewall is running...")
