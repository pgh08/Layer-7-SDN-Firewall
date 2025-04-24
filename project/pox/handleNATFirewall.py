from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# NAT implementation
def nat_handler(event):
    packet = event.parsed
    print(packet.type, packet.IP_TYPE)
    if packet.type == packet.IP_TYPE:
        ip_packet = packet.payload
        # Implement NAT for TCP packets
        # Modify source/destination IP addresses and ports as needed
        # Install flow rules on the switch to perform NAT
        # Example:
        new_src_ip = ip_packet.srcip
        new_dst_ip = ip_packet.dstip
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.actions.append(of.ofp_action_nw_addr.set_src(new_src_ip))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(new_dst_ip))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        event.connection.send(msg)
    elif packet.type == packet.ARP_TYPE:
        # Implement NAT for TCP packets
        # Modify source/destination IP addresses and ports as needed
        # Install flow rules on the switch to perform NAT
        # Example:
        arpPacket = packet.payload
        new_src_ip = arpPacket.protosrc
        new_dst_ip = arpPacket.protodst
        print(new_dst_ip, new_src_ip)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.actions.append(of.ofp_action_nw_addr.set_src(new_src_ip))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(new_dst_ip))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        event.connection.send(msg)

# Start the NAT handler
def launch():
    core.openflow.addListenerByName("PacketIn", nat_handler)
    log.debug("NAT module started")
