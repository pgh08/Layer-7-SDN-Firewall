from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import re

# List of keywords to block
BLOCKED_KEYWORDS = ['block', 'keyword']

# Event handler for packet-in event
def _handle_PacketIn(event):
    packet = event.parsed
    tcp_packet = packet.find('tcp')
    
    if tcp_packet is None:
        return

    tcp_payload = tcp_packet.payload
    if isinstance(tcp_payload, str):
        for keyword in BLOCKED_KEYWORDS:
            if re.search(keyword, tcp_payload, re.IGNORECASE):
                print(f"Blocking packet with keyword '{keyword}' from {event.connection.dpid}")
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = event.port
                event.connection.send(msg)
                return

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    print("Layer 7 Firewall is running...")

