from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.packet.udp import udp
from pox.lib.packet import ethernet
from pox.lib.recoco import Timer
import time

log = core.getLogger()

# Global time for handling request after dos attack.
# attackStartTime = time.time()
# lastAttackTime = time.time()

# To store DOS attack state.
dosState = {}

# Maintaining connection state.
connection_state = {}

# Global count.
timeCount = 0

# IP List for blocking.
blockedIPs = ['10.0.0.1', '10.0.0.3']

# Port List for blocking.
blockedPorts = [1, 4]

# PacketCount for DoS attack.
packetCount = {}

# Maximum allowed packet count per second per host.
MAX_PACKETS_PER_SEC = 20

# String to store known malicious message.
malicious1 = "malicious1"
malicious2 = "malicious2"

def reset_flow_table():
    for connection in core.openflow.connections:
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        connection.send(msg)

def install_flow_mod(connection, msg):
    connection.send(msg)

def install_flow_rule(connection, msg, packet, event):
    msg.data = event.ofp
    msg.in_port = event.port
    # msg.match = of.ofp_match()
    # msg.idle_timeout = 60
    # action = of.ofp_action_output(port=of.OFPP_NONE)
    # msg.actions.append(action)
    install_flow_mod(connection, msg)
    return

def install_ping_rule(connection, dl_type):
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match._dl_type = dl_type
    action = of.ofp_action_output(port=of.OFPP_NORMAL)
    msg.actions.append(action)
    install_flow_mod(connection, msg)

# Blocking IP code.
def ipBlocker(sourceIP):
    print(f"Request from ip {sourceIP} is blocked")

# Blocking Port code.
def portBlocker(port):
    print(f"Request from port {port} is blocked")

def check_and_block(ip, port, event, packet):
    if ip in blockedIPs:
        ipBlocker(ip)
        # install_flow_rule(event.connection, of.ofp_flow_mod(), packet, event)
        return True
    elif port in blockedPorts:
        portBlocker(port)
        # install_flow_rule(event.connection, of.ofp_flow_mod(), packet, event)
        return True
    return False

def normalFlowPing(arpPacket, dl_type, event):
    nw_src = arpPacket.protosrc
    nw_port = event.port

    if check_and_block(nw_src, nw_port, event, arpPacket):
        return
    else:
        install_ping_rule(event.connection, dl_type)
        time.sleep(2)
        reset_flow_table()
        return

def doFirewallThing(ipPacket, event):
    src_ip = ipPacket.srcip
    port = event.port

    if check_and_block(src_ip, port, event, ipPacket):
        return

    if src_ip not in packetCount:
        packetCount[src_ip] = 0

    packetCount[src_ip] += 1

    if src_ip != IPAddr('10.0.0.8') and packetCount[src_ip] > MAX_PACKETS_PER_SEC:
        print(f"DoS attack detected from {src_ip}, blocking traffic from {src_ip}...")
        if src_ip not in dosState:
            dosState[src_ip] = True
            install_flow_rule(event.connection, of.ofp_flow_mod(), ipPacket, event)
        else:
            return

def doIDS(ipPacket, event):
    src_ip = ipPacket.srcip
    port = event.port

    if check_and_block(src_ip, port, event, ipPacket):
        return

    if isinstance(ipPacket.payload, udp):
        udpPacket = ipPacket.payload
        message = udpPacket.payload
        intrusionSignature = str(message)
        if intrusionSignature.find(malicious1) != -1 or intrusionSignature.find(malicious2) != -1:
            print(f"Intrusion detected from {src_ip} blocking traffic...")
            install_flow_rule(event.connection, of.ofp_flow_mod(), ipPacket, event)
            return

def protocolBased(ipPacket, event):
    src_ip = ipPacket.srcip

    if ipPacket.protocol == ipPacket.TCP_PROTOCOL and (ipPacket.payload.srcport == 80 or ipPacket.payload.dstport == 80):
        print(f"HTTP request detected from {src_ip}, blocking HTTP traffic...")
        install_flow_rule(event.connection, of.ofp_flow_mod(), ipPacket, event)
        return
    
def doNormalPing(ipPacket, dl_type, event):
    nw_src = ipPacket.srcip
    nw_port = event.port

    if check_and_block(nw_src, nw_port, event, ipPacket):
        return
    else:
        if nw_src not in packetCount:
            packetCount[nw_src] = 0

        packetCount[nw_src] += 1
        
        if packetCount[nw_src] > MAX_PACKETS_PER_SEC:
            doFirewallThing(ipPacket, event)
            return

        install_ping_rule(event.connection, dl_type)
        return

def doStateFullmonitoring(ipPacket, event):
    nw_src = ipPacket.srcip
    nw_port = event.port

    if check_and_block(nw_src, nw_port, event, ipPacket):
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
            print(connection_state)
            return

def _handle_PacketIn(event):
    packet = event.parsed
    if packet.type == ethernet.IP_TYPE:
        ipPacket = packet.payload

        # If normal ICMP.
        if packet.payload.protocol == packet.payload.ICMP_PROTOCOL:
            doNormalPing(ipPacket, ethernet.IP_TYPE, event)

        # If DoS attack.
        doFirewallThing(ipPacket, event)

        # If IDS signature based.
        doIDS(ipPacket, event)

        # If HTTP packet.
        protocolBased(ipPacket, event)

        # Stateful monitoring and flow addition.
        doStateFullmonitoring(ipPacket, event)

    elif packet.type == ethernet.ARP_TYPE:
        arpPacket = packet.payload
        normalFlowPing(arpPacket, ethernet.ARP_TYPE, event)
        return

def _handle_FlowRemoved(event):
    if event.ofp.reason == of.OFPRR_IDLE_TIMEOUT:
        # If a flow entry is removed due to idle timeout, remove the corresponding state
        connection_state.pop((event.match.nw_src, event.match.tp_src, event.match.nw_dst, event.match.tp_dst), None)
        dosState.clear()


def _handle_ConnectionDown(event):
    # Clear all state when a switch disconnects
    connection_state.clear()
    dosState.clear()

def launch():
    def start_timer():
        Timer(10, reset_flow_table, recurring=True)
        log.info("Flow table reset timer started.")

    print("Starting firewall\n")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("FlowRemoved", _handle_FlowRemoved)
    core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)
    core.openflow.addListenerByName("ConnectionUp", lambda event: start_timer())