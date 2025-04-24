from pox.core import core
import pox.openflow.libopenflow_01 as of

# List of IP addresses to block
BLOCKED_IPS = ['10.0.0.10', '192.168.1.2']

def _handle_PacketIn(event):
    packet = event.parsed

    if packet.type == packet.ARP_TYPE:
        arp_packet = packet.payload
        src_ip = arp_packet.protosrc
        dst_ip = arp_packet.protodst
        # print(f"ARP Packet : Source IP = {src_ip}, Destination IP = {dst_ip}")
        msg = of.ofp_flow_mod()
        msg.match._dl_type = packet.ARP_TYPE
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)
        return


    if packet.type != packet.IP_TYPE:
        return

    ip_packet = packet.payload
    src_ip = ip_packet.srcip
    dst_ip = ip_packet.dstip

    if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
        # Blocked IP address detected, drop the packet
        print(f"Blocking packet from/to {src_ip}/{dst_ip}...")
        msg = of.ofp_packet_out()   
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)
        return  

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    print("IP Blocker is running...")
