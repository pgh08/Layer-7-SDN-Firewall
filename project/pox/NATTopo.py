from mininet.cli import CLI
from mininet.log import lg, info
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSController

class customTopo(Topo):
    def build(self):

        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        h5 = self.addHost('h5', ip='10.0.0.5/24')
        h6 = self.addHost('h6', ip='10.0.0.6/24')
        h7 = self.addHost('h7', ip='10.0.0.7/24')

        s1 = self.addSwitch('s1')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)
        self.addLink(h5, s1)
        self.addLink(h6, s1)
        self.addLink(h7, s1)
        
if __name__ == '__main__':
    lg.setLogLevel('info')
    # net = Mininet(topo=customTopo(), controller=OVSController ,ipBase='10.0.0.0/24')
    net = Mininet(topo=customTopo(), controller=RemoteController, ipBase='10.0.0.0/24')
    
    # Adding NAT connectivity.
    net.addNAT().configDefault()
    net.start()

    info( "*** Hosts are running and should have internet connectivity\n" )
    info( "*** Type 'exit' or control-D to shut down network\n" )


    CLI( net )

    # To shut down NAT.
    net.stop()