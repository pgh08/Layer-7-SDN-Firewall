from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.packet.udp import udp

blockedIPs = ['10.0.0.11', '10.0.0.10']

# PacketCount for DoS attack.
packetCount = {}
    
# Maximum allowed packet count per second per host.
MAX_PACKETS_PER_SEC = 20

# String to store known malicious message.
malicious1 = "malicious1"
malicious2 = "malicious2"

# Blocking IP code.
def ipBlocker(sourceIP):
    print(f"Request from {sourceIP} is blocked")

def normalFlowPing(arpPacket, dl_type, event):
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    nw_src = arpPacket.protosrc
    nw_dst = arpPacket.protodst
    msg.match._dl_type = dl_type
    if nw_src in blockedIPs:
        ipBlocker(nw_src)
        msg = of.ofp_flow_mod()
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)
        return
    else:
        if nw_src not in packetCount:
            packetCount[nw_src] = 0

        packetCount[nw_src] += 1

        if packetCount[nw_src] > MAX_PACKETS_PER_SEC:
            print(f"DoS attack detected from {nw_src}, blocking traffic from {nw_src}...")
            msg = of.ofp_flow_mod()
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)
            return

        action = of.ofp_action_output(port = of.OFPP_NORMAL)
        msg.actions.append(action)
        event.connection.send(msg)
        return

def doFirewallThing(ipPacket, event):
    src_ip = ipPacket.srcip

    if src_ip in blockedIPs:
        ipBlocker(src_ip)
        msg = of.ofp_flow_mod()
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)
        return

    if src_ip not in packetCount:
        packetCount[src_ip] = 0

    packetCount[src_ip] += 1
        
    if packetCount[src_ip] > MAX_PACKETS_PER_SEC:
        print(f"DoS attack detected from {src_ip}, blocking traffic from {src_ip}...")
        msg = of.ofp_flow_mod()
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)
        return

def doIDS(ipPacket, event):
    src_ip = ipPacket.srcip

    if src_ip in blockedIPs:
        ipBlocker(src_ip)
        msg = of.ofp_flow_mod()
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)
        return
    
    if isinstance(ipPacket.payload, udp):
        udpPacket = ipPacket.payload
        message = udpPacket.payload
        intrusionSignature = message.decode('utf-8')

        if intrusionSignature.find(malicious1) != -1 or intrusionSignature.find(malicious2) != -1:
            print(f"Intrusion detected : {intrusionSignature}, blocking traffic...")
            msg = of.ofp_flow_mod()
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)
            return

def _handle_PacketIn(event):
    packet = event.parsed
    if packet.type == packet.IP_TYPE:
        ipPacket = packet.payload

        # If DoS attack.
        DoS = doFirewallThing(ipPacket, event)

        # If IDS signature based.
        IDS = doIDS(ipPacket, event)

    elif packet.type == packet.ARP_TYPE:
        arpPacket = packet.payload
        normalFlowPing(arpPacket, packet.ARP_TYPE, event)
        return

def launch():

    print("Starting firewall\n")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)