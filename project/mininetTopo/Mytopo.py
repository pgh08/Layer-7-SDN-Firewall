from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink

class CustomTopology(Topo):
    def build(self):
        switch = self.addSwitch('s1', flood_all=True)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        self.addLink(h1, switch)
        self.addLink(h2, switch)

topo = CustomTopology()
net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1'), link=TCLink)
net.start()
net.pingAll()
net.stop()

