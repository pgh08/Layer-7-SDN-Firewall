from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import SingleSwitchTopo
import time

def send_tcp_message(host_ip, host_port, message):
    h1 = net.get('h1')
    h1.cmd('echo "{}" | nc {} {}'.format(message, host_ip, host_port))

# Create Mininet topology
topo = SingleSwitchTopo(1)
net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1'))

# Start Mininet
net.start()

# Configure NAT on Mininet host (h1)
net.get('h1').cmd('iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE')

# External host IP and port
external_host_ip = '192.168.1.2'
external_host_port = '12345'

# Send TCP message from h1 to external host
send_tcp_message(external_host_ip, external_host_port, 'Hello, world!')

# Wait for message to be sent
time.sleep(1)

# Stop Mininet
net.stop()
