from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.icmp import icmp
from collections import defaultdict
import time
import threading

log = core.getLogger()

class MultiLayerFirewall(object):
    """
    Firewall multi-couches détectant plusieurs types d'attaques DDoS :
    - SYN Flood (Layer 4)
    - UDP Flood (Layer 4)
    - ICMP Flood (Layer 3)
    - ACK/RST Flood (Layer 4)
    """
    
    # === CONFIGURATION DES SEUILS ===
    SEUIL_SYN = 50          # Paquets SYN par seconde
    SEUIL_UDP = 100         # Paquets UDP par seconde
    SEUIL_ICMP = 50         # Paquets ICMP par seconde
    SEUIL_ACK = 200         # Paquets ACK par seconde
    
    FENETRE_TEMPS = 1.0     # Fenêtre de mesure en secondes
    DUREE_BLOCAGE = 60      # Durée du blocage en secondes
    
    # IPs à ne JAMAIS bloquer
    WHITELIST = {
        "10.0.1.10",  # Serveur web
    }
    
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Firewall multi-couches connecté au switch %s", connection)
        
        # Compteurs par IP source et type d'attaque
        self.syn_counts = defaultdict(int)
        self.udp_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.ack_counts = defaultdict(int)
        
        self.last_reset = time.time()
        self.blocked_ips = {}  # {ip: (timestamp, raison)}
        
        # CORRECTION: Ajout de verrous pour thread safety
        self.counters_lock = threading.Lock()
        self.blocked_lock = threading.Lock()
    
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return
        
        self._unblock_expired_ips()
        
        if packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.payload
            src_ip = ip_pkt.srcip.toStr()
            
            # Whitelist : toujours autoriser
            if src_ip in self.WHITELIST:
                self._forward_packet(event)
                return
            
            # CORRECTION: Si déjà bloqué, DROP sans forward
            with self.blocked_lock:
                if src_ip in self.blocked_ips:
                    log.debug("Paquet DROP de %s (déjà bloqué)", src_ip)
                    return  # Ne pas forward
            
            # CORRECTION: Vérifier d'abord si attaque détectée avant de forward
            is_attack = False
            
            with self.counters_lock:
                # === DÉTECTION TCP (SYN, ACK) ===
                if ip_pkt.protocol == ipv4.TCP_PROTOCOL:
                    tcp_seg = ip_pkt.payload
                    
                    # Détection SYN Flood
                    if tcp_seg.SYN and not tcp_seg.ACK:
                        self.syn_counts[src_ip] += 1
                        if self.syn_counts[src_ip] > self.SEUIL_SYN:
                            is_attack = True
                    
                    # Détection ACK Flood (ACK sans SYN)
                    elif tcp_seg.ACK and not tcp_seg.SYN:
                        self.ack_counts[src_ip] += 1
                        if self.ack_counts[src_ip] > self.SEUIL_ACK:
                            is_attack = True
                
                # === DÉTECTION UDP FLOOD ===
                elif ip_pkt.protocol == ipv4.UDP_PROTOCOL:
                    self.udp_counts[src_ip] += 1
                    if self.udp_counts[src_ip] > self.SEUIL_UDP:
                        is_attack = True
                
                # === DÉTECTION ICMP FLOOD (Ping flood) ===
                elif ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
                    self.icmp_counts[src_ip] += 1
                    if self.icmp_counts[src_ip] > self.SEUIL_ICMP:
                        is_attack = True
            
            # CORRECTION: Si attaque détectée, bloquer IMMÉDIATEMENT et ne pas forward
            if is_attack:
                now = time.time()
                self._block_ip_immediate(src_ip, now, event)
                return  # Ne PAS forward le paquet
            
            # Vérifier les seuils toutes les secondes
            now = time.time()
            if now - self.last_reset >= self.FENETRE_TEMPS:
                self._check_and_block_all_attacks(now)
                self._clear_counters()
                self.last_reset = now
            
            # Forward le paquet SEULEMENT si pas d'attaque
            self._forward_packet(event)
        else:
            # Autre type de paquet
            self._forward_packet(event)
    
    def _check_and_block_all_attacks(self, now):
        """Vérifie tous les types d'attaques et bloque si nécessaire"""
        
        with self.counters_lock:
            # Vérifier SYN Flood
            for ip, count in self.syn_counts.items():
                if count > self.SEUIL_SYN:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self._block_ip(ip, now, f"SYN Flood ({count} SYN/s)")
            
            # Vérifier UDP Flood
            for ip, count in self.udp_counts.items():
                if count > self.SEUIL_UDP:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self._block_ip(ip, now, f"UDP Flood ({count} UDP/s)")
            
            # Vérifier ICMP Flood
            for ip, count in self.icmp_counts.items():
                if count > self.SEUIL_ICMP:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self._block_ip(ip, now, f"ICMP Flood ({count} ICMP/s)")
            
            # Vérifier ACK Flood
            for ip, count in self.ack_counts.items():
                if count > self.SEUIL_ACK:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self._block_ip(ip, now, f"ACK Flood ({count} ACK/s)")
    
    def _block_ip_immediate(self, ip, timestamp, event):
        """Bloque une IP immédiatement lors de détection en temps réel"""
        with self.blocked_lock:
            if ip in self.blocked_ips:
                return  # Déjà bloqué
            
            protocol = "UNKNOWN"
            with self.counters_lock:
                if self.syn_counts[ip] > self.SEUIL_SYN:
                    protocol = f"SYN Flood ({self.syn_counts[ip]} SYN/s)"
                elif self.udp_counts[ip] > self.SEUIL_UDP:
                    protocol = f"UDP Flood ({self.udp_counts[ip]} UDP/s)"
                elif self.icmp_counts[ip] > self.SEUIL_ICMP:
                    protocol = f"ICMP Flood ({self.icmp_counts[ip]} ICMP/s)"
                elif self.ack_counts[ip] > self.SEUIL_ACK:
                    protocol = f"ACK Flood ({self.ack_counts[ip]} ACK/s)"
            
            self._block_ip(ip, timestamp, protocol)
    
    def _block_ip(self, ip, timestamp, raison):
        """Bloque une IP avec règle OpenFlow DROP"""
        log.warning("[ALERTE DDoS] %s détecté de %s - BLOCAGE", raison, ip)
        
        # CORRECTION: Installer règle de DROP (pas d'action = DROP)
        fm = of.ofp_flow_mod()
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.nw_src = ip
        fm.priority = 1000
        fm.hard_timeout = self.DUREE_BLOCAGE
        # Pas d'action ajoutée = DROP automatique
        self.connection.send(fm)
        
        self.blocked_ips[ip] = (timestamp, raison)
        log.info("→ %s bloqué pour %ds", ip, self.DUREE_BLOCAGE)
    
    def _unblock_expired_ips(self):
        """Débloque les IPs après expiration du timeout"""
        now = time.time()
        with self.blocked_lock:
            expired = [
                ip for ip, (ts, _) in self.blocked_ips.items()
                if now - ts > self.DUREE_BLOCAGE
            ]
            for ip in expired:
                raison = self.blocked_ips[ip][1]
                del self.blocked_ips[ip]
                log.info("✓ %s débloqué (timeout expiré - était bloqué pour %s)", ip, raison)
    
    def _clear_counters(self):
        """Réinitialise tous les compteurs"""
        self.syn_counts.clear()
        self.udp_counts.clear()
        self.icmp_counts.clear()
        self.ack_counts.clear()
    
    def _forward_packet(self, event):
        """Forward un paquet normalement"""
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)


def launch():
    """Lance le contrôleur firewall"""
    def start_switch(event):
        log.info("Connexion switch au firewall multi-couches")
        MultiLayerFirewall(event.connection)
    
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("=== Contrôleur Firewall Multi-Couches Démarré ===")
    log.info("Protection contre: SYN/UDP/ICMP/ACK Floods")
