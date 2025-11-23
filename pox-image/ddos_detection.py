from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import EthAddr
from collections import defaultdict
import time
import threading

log = core.getLogger()

class MultiLayerFirewall(object):
    # --- PARAMÈTRES DE DÉTECTION (Basés sur un taux par seconde) ---
    SEUIL_SYN = 50
    SEUIL_UDP = 50
    SEUIL_ICMP = 50
    SEUIL_ACK = 200

    FENETRE_TEMPS = 1.0  # Durée de la fenêtre de temps en secondes
    DUREE_BLOCAGE = 10   # Durée du blocage en secondes

    WHITELIST = {
        "10.0.1.10", # Exemple: Le serveur Web cible qui génère aussi du trafic légitime
    }

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Firewall [DOS] connecté au switch %s", connection)

        # Compteurs pour la détection basée sur la fenêtre de temps
        self.syn_counts = defaultdict(int)
        self.udp_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.ack_counts = defaultdict(int)

        self.last_reset = time.time()
        self.blocked_ips = {}    # {ip: (timestamp, raison)}
        self.blocked_macs = {}   # {mac: (timestamp, raison)}

        # Verrous pour l'accès concurrent aux données
        self.counters_lock = threading.Lock()
        self.blocked_lock = threading.Lock()
        
    def _handle_PacketIn(self, event):
        try:
            packet = event.parsed
            if not packet or not packet.parsed:
                return
        except AttributeError as e:
            return

        self._unblock_expired_ips()

        # Traitement du trafic IP (Couches 3/4)
        if packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.payload
            src_ip = ip_pkt.srcip.toStr()
            src_mac = str(packet.src)

            if src_ip in self.WHITELIST:
                self._forward_packet(event)
                return

            with self.blocked_lock:
                if src_ip in self.blocked_ips:
                    log.debug("Paquet DROP de %s (déjà bloqué IP)", src_ip)
                    return

            # --- LOGIQUE DE COMPTAGE UNIQUE (MÉCANISME PÉRIODIQUE) ---
            with self.counters_lock:
                if ip_pkt.protocol == ipv4.TCP_PROTOCOL:
                    tcp_seg = ip_pkt.payload
                    if tcp_seg.SYN and not tcp_seg.ACK:
                        self.syn_counts[src_ip] += 1
                    # Compte les paquets ACK (ACK flood)
                    elif tcp_seg.ACK and not tcp_seg.SYN:
                        self.ack_counts[src_ip] += 1
                
                elif ip_pkt.protocol == ipv4.UDP_PROTOCOL:
                    self.udp_counts[src_ip] += 1
                
                elif ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
                    self.icmp_counts[src_ip] += 1

            # --- VÉRIFICATION DE LA FENÊTRE DE TEMPS ET BLOCAGE ---
            now = time.time()
            if now - self.last_reset >= self.FENETRE_TEMPS:
                self._check_and_block_all_attacks(now)
                self._clear_counters()
                self.last_reset = now

            self._forward_packet(event)
            
        # Traitement du trafic non-IP (L2/ARP)
        else:
            src_mac_l2 = str(packet.src)
            with self.blocked_lock:
                if src_mac_l2 in self.blocked_macs:
                    log.debug("DROP non-IP de MAC bloquée %s", src_mac_l2)
                    return
            self._forward_packet(event)

    def _check_and_block_all_attacks(self, now):
        """
        Vérifie tous les compteurs et bloque si un seuil est dépassé.
        Ceci est appelé UNIQUEMENT à la fin de la fenêtre de temps.
        """
        
        # Liste des attaques détectées dans cette fenêtre
        detected_attacks = {} # {ip: (count, seuil, raison)}

        with self.counters_lock:
            for ip, count in self.syn_counts.items():
                if count > self.SEUIL_SYN:
                    detected_attacks[ip] = (count, self.SEUIL_SYN, "SYN Flood")
            for ip, count in self.udp_counts.items():
                if count > self.SEUIL_UDP:
                    detected_attacks[ip] = (count, self.SEUIL_UDP, "UDP Flood")
            for ip, count in self.icmp_counts.items():
                if count > self.SEUIL_ICMP:
                    detected_attacks[ip] = (count, self.SEUIL_ICMP, "ICMP Flood")
            for ip, count in self.ack_counts.items():
                if count > self.SEUIL_ACK:
                    detected_attacks[ip] = (count, self.SEUIL_ACK, "ACK Flood")
        
        # Appliquer les blocages
        for ip, (count, seuil, raison) in detected_attacks.items():
            if ip in self.WHITELIST:
                continue

            with self.blocked_lock:
                if ip not in self.blocked_ips:
                    
                    log.warning("[ALERTE DDoS] détecté de %s (%d paq/s > %d) - BLOCAGE", ip, count, seuil)
                                
                    self._block_ip(ip, now, f"{raison} ({count} paq/s)")
                

    def _block_ip(self, ip, timestamp, raison):
        """Bloque une adresse IP source au niveau OpenFlow (L3)."""
        fm = of.ofp_flow_mod()
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.nw_src = ip
        fm.priority = 2000
        fm.hard_timeout = self.DUREE_BLOCAGE
        self.connection.send(fm)

        self.blocked_ips[ip] = (timestamp, raison)
        log.info("%s bloqué (IP) pour %ds", ip, self.DUREE_BLOCAGE)

    
    def _block_mac_l2(self, mac):
        # ... (Identique au code original)
        try:
            ea = EthAddr(mac)
        except Exception:
            log.error("EthAddr invalide pour %s", mac)
            return
        fm = of.ofp_flow_mod()
        fm.match.dl_src = ea
        fm.priority = 1900
        fm.hard_timeout = self.DUREE_BLOCAGE
        self.connection.send(fm)
        log.info("MAC %s bloquée (L2) pour %ds", mac, self.DUREE_BLOCAGE)

    def _block_arp_from_mac(self, mac):
        # ... (Identique au code original)
        try:
            ea = EthAddr(mac)
        except Exception:
            log.error("EthAddr invalide pour %s", mac)
            return
        fm = of.ofp_flow_mod()
        fm.match.dl_type = ethernet.ARP_TYPE
        fm.match.dl_src = ea
        fm.priority = 1950
        fm.hard_timeout = self.DUREE_BLOCAGE
        self.connection.send(fm)
        log.info("MAC %s bloquée (ARP) pour %ds", mac, self.DUREE_BLOCAGE)
        
    def _unblock_expired_ips(self):
        # ... (Identique au code original)
        now = time.time()
        with self.blocked_lock:
            expired_ip = [ip for ip, (ts, _) in self.blocked_ips.items() if now - ts > self.DUREE_BLOCAGE]
            for ip in expired_ip:
                raison = self.blocked_ips[ip][1]
                del self.blocked_ips[ip]
                log.info("%s débloqué (timeout expiré)", ip)

            expired_mac = [m for m, (ts, _) in self.blocked_macs.items() if now - ts > self.DUREE_BLOCAGE]
            for m in expired_mac:
                del self.blocked_macs[m]

    def _clear_counters(self):
        # ... (Identique au code original)
        with self.counters_lock:
            self.syn_counts.clear()
            self.udp_counts.clear()
            self.icmp_counts.clear()
            self.ack_counts.clear()

    def _forward_packet(self, event):
        # ... (Identique au code original)
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        # NOTE: OFPP_FLOOD est utilisé par défaut. Un L2-learning complet 
        # serait préférable pour le trafic légitime.
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

def launch():
    def start_switch(event):
        MultiLayerFirewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("=== Contrôleur POX DOS Defense démarré ===")