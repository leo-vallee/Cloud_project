from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def customTopology():
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)

    # Ajouter le controller distant
    net.addController('c0', ip='172.18.0.2', port=6633)

    # Sous-réseau 1
    h1 = net.addHost('h1', ip='10.0.1.10/24')  # Serveur web
    h2 = net.addHost('h2', ip='10.0.1.11/24')  # Générateur trafic
    h3 = net.addHost('h3', ip='10.0.1.12/24')  # Générateur trafic
    s1 = net.addSwitch('s1')

    # Sous-réseau 2
    h4 = net.addHost('h4', ip='10.0.2.10/24')  # Client HTTP
    h5 = net.addHost('h5', ip='10.0.2.11/24')  # Client HTTP
    h6 = net.addHost('h6', ip='10.0.2.20/24')  # Attaquant
    s2 = net.addSwitch('s2')

    # Routeur entre les deux sous-réseaux (double interface, deux IPs)
    router = net.addHost('r0', ip='10.0.1.1/24')

    # Liens réseau
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s2)
    net.addLink(h5, s2)
    net.addLink(h6, s2)

    # Lien routeur - switch
    link1 = net.addLink(router, s1)
    link2 = net.addLink(router, s2)

    net.start()

    # Configurer le routage IP sur le routeur - attribuer 2e IP sur interface r0-eth1
    router.cmd('ifconfig r0-eth1 10.0.2.1/24')

    # Activer routage IP (forwarding) sur le routeur
    router.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Routes par défaut sur les hôtes vers leur passerelle respective (le routeur)
    for h in [h1, h2, h3]:
        h.cmd('ip route add default via 10.0.1.1')

    for h in [h4, h5, h6]:
        h.cmd('ip route add default via 10.0.2.1')

    print('Lancement du serveur web H1')
    h1.cmd('python3 -m http.server 80 &')

    h2.cmd('while true; do curl -s http://10.0.1.10 > /dev/null; sleep 3; done &')
    h3.cmd('while true; do curl -s http://10.0.1.10 > /dev/null; sleep 3; done &')

    h4.cmd('curl -s http://10.0.1.10 &')
    h5.cmd('curl -s http://10.0.1.10 &')

    print("ATTAQUE DE H6 VERS H1 (DDOS)")
    h6.cmd('for i in {1..100}; do (nc -w 0 10.0.1.10 80 &); done')

    # h6.cmd('for i in {1..150}; do echo "ATTACK" | nc -u -w 0 10.0.1.10 53; done')

    # h6.cmd('ping -f -c 100 10.0.1.10')

    print('TEST DE CURL H1 : ')
    output = h6.cmd('curl -s --connect-timeout 3 --max-time 5 http://10.0.1.10')
    if output:
        print("Réponse reçue :")
        print(output)
    else:
        print("Aucune réponse (timeout ou bloqué)")

    # Lancer CLI pour debug
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    customTopology()
