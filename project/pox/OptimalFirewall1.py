from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.packet.udp import udp
from pox.lib.packet import ethernet, ipv4, tcp

# Maintain connection state
connection_state = {}

# IP and Port Lists for blocking
blockedIPs = {'10.0.0.4', '10.0.0.10'}
blockedPorts = {1, 4}

# Packet count for DoS attack
packetCount = {}

# Maximum allowed packet count per second per host
MAX_PACKETS_PER_SEC = 20

# Malicious messages
malicious_messages = {"malicious1", "malicious2"}

def install_flow_mod(connection, msg):
    connection.send(msg)

def install_flow_rule(connection, msg, packet, event):
    msg.data = event.ofp
    msg.in_port = event.port
    install_flow_mod(connection, msg)

def install_ping_rule(connection, dl_type):
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match._dl_type = dl_type
    action = of.ofp_action_output(port=of.OFPP_NORMAL)
    msg.actions.append(action)
    install_flow_mod(connection, msg)

def ipBlocker(sourceIP):
    print(f"Request from IP {sourceIP} is blocked")

def portBlocker(port):
    print(f"Request from port {port} is blocked")

def check_and_block(ip, port, event, packet):
    if ip in blockedIPs:
        ipBlocker(ip)
        return True
    elif port in blockedPorts:
        portBlocker(port)
        return True
    return False

def normalFlowPing(arpPacket, dl_type, event):
    nw_src = arpPacket.protosrc
    nw_port = event.port

    if check_and_block(nw_src, nw_port, event, arpPacket):
        return
    else:
        install_ping_rule(event.connection, dl_type)
        return

def handle_ping(ipPacket, dl_type, event):
    nw_src = ipPacket.srcip
    nw_port = event.port

    if check_and_block(nw_src, nw_port, event, ipPacket):
        return
    else:
        install_ping_rule(event.connection, dl_type)

def handle_dos_attack(ipPacket, event):
    src_ip = ipPacket.srcip
    port = event.port
    
    if check_and_block(src_ip, port, event, ipPacket):
        return

    if src_ip not in packetCount:
        packetCount[src_ip] = 0

    packetCount[src_ip] += 1

    if src_ip != IPAddr('10.0.0.8') and packetCount[src_ip] > MAX_PACKETS_PER_SEC:
        print(f"DoS attack detected from {src_ip}, blocking traffic from {src_ip}...")
        install_flow_rule(event.connection, of.ofp_flow_mod(), ipPacket, event)

def handle_ids(ipPacket, event):
    src_ip = ipPacket.srcip
    port = event.port

    if check_and_block(src_ip, port, event, ipPacket):
        return

    if isinstance(ipPacket.payload, udp):
        udpPacket = ipPacket.payload
        message = udpPacket.payload
        intrusionSignature = str(message)
        if any(sig in intrusionSignature for sig in malicious_messages):
            print(f"Intrusion detected from {src_ip}, blocking traffic...")
            install_flow_rule(event.connection, of.ofp_flow_mod(), ipPacket, event)

def handle_http_traffic(ipPacket, event):
    src_ip = ipPacket.srcip

    if ipPacket.protocol == ipPacket.TCP_PROTOCOL and (ipPacket.payload.srcport == 80 or ipPacket.payload.dstport == 80):
        print(f"HTTP request detected from {src_ip}, blocking HTTP traffic...")
        install_flow_rule(event.connection, of.ofp_flow_mod(), ipPacket, event)

def handle_stateful_monitoring(ipPacket, event):
    src_ip = ipPacket.srcip
    nw_port = event.port

    if check_and_block(src_ip, nw_port, event, ipPacket):
        return
    elif ipPacket.protocol == ipPacket.TCP_PROTOCOL:
        tcp_packet = ipPacket.payload
        src_ip = ipPacket.srcip
        dst_ip = ipPacket.dstip
        src_port = tcp_packet.srcport
        dst_port = tcp_packet.dstport

        if (src_ip, src_port, dst_ip, dst_port) not in connection_state:
            connection_state[(src_ip, src_port, dst_ip, dst_port)] = True
            install_flow_rule(event.connection, of.ofp_flow_mod(), ipPacket, event)

def _handle_PacketIn(event):
    packet = event.parsed

    if packet.type == ethernet.IP_TYPE:
        ipPacket = packet.payload

        if packet.payload.protocol == packet.payload.ICMP_PROTOCOL:
            handle_ping(ipPacket, ethernet.IP_TYPE, event)

        handle_dos_attack(ipPacket, event)
        handle_ids(ipPacket, event)
        handle_http_traffic(ipPacket, event)
        handle_stateful_monitoring(ipPacket, event)

    elif packet.type == ethernet.ARP_TYPE:
        arpPacket = packet.payload
        normalFlowPing(arpPacket, ethernet.ARP_TYPE, event)

def _handle_FlowRemoved(event):
    if event.ofp.reason == of.OFPRR_IDLE_TIMEOUT:
        connection_state.pop((event.match.nw_src, event.match.tp_src, event.match.nw_dst, event.match.tp_dst), None)

def _handle_ConnectionDown(event):
    connection_state.clear()

def launch():
    print("Starting firewall\n")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("FlowRemoved", _handle_FlowRemoved)
    core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)