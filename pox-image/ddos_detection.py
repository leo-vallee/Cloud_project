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
    SEUIL_SYN = 50
    SEUIL_UDP = 100
    SEUIL_ICMP = 50
    SEUIL_ACK = 200

    FENETRE_TEMPS = 1.0
    DUREE_BLOCAGE = 60

    WHITELIST = {
        "10.0.1.10",
    }

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Firewall multi-couches connecté au switch %s", connection)

        self.syn_counts = defaultdict(int)
        self.udp_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.ack_counts = defaultdict(int)

        self.last_reset = time.time()
        self.blocked_ips = {}   # {ip: (timestamp, raison)}
        self.blocked_macs = {}  # {mac: (timestamp, raison)}  # facultatif si tu veux tracer

        self.counters_lock = threading.Lock()
        self.blocked_lock = threading.Lock()

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet or not packet.parsed:
            return

        self._unblock_expired_ips()

        if packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.payload
            src_ip = ip_pkt.srcip.toStr()

            if src_ip in self.WHITELIST:
                self._forward_packet(event)
                return

            with self.blocked_lock:
                if src_ip in self.blocked_ips:
                    log.debug("Paquet DROP de %s (déjà bloqué IP)", src_ip)
                    return

            is_attack = False
            with self.counters_lock:
                if ip_pkt.protocol == ipv4.TCP_PROTOCOL:
                    tcp_seg = ip_pkt.payload
                    if tcp_seg.SYN and not tcp_seg.ACK:
                        self.syn_counts[src_ip] += 1
                        if self.syn_counts[src_ip] > self.SEUIL_SYN:
                            is_attack = True
                    elif tcp_seg.ACK and not tcp_seg.SYN:
                        self.ack_counts[src_ip] += 1
                        if self.ack_counts[src_ip] > self.SEUIL_ACK:
                            is_attack = True
                elif ip_pkt.protocol == ipv4.UDP_PROTOCOL:
                    self.udp_counts[src_ip] += 1
                    if self.udp_counts[src_ip] > self.SEUIL_UDP:
                        is_attack = True
                elif ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
                    self.icmp_counts[src_ip] += 1
                    if self.icmp_counts[src_ip] > self.SEUIL_ICMP:
                        is_attack = True

            if is_attack:
                now = time.time()
                self._block_ip_immediate(src_ip, now, event)
                return

            now = time.time()
            if now - self.last_reset >= self.FENETRE_TEMPS:
                self._check_and_block_all_attacks(now)
                self._clear_counters()
                self.last_reset = now

            self._forward_packet(event)
        else:
            # Laisse passer non-IP (ARP/L2) sauf si la MAC est déjà bloquée par renforcement
            src_mac_l2 = str(packet.src)
            with self.blocked_lock:
                if src_mac_l2 in self.blocked_macs:
                    log.debug("DROP non-IP de MAC bloquée %s", src_mac_l2)
                    return
            self._forward_packet(event)

    def _check_and_block_all_attacks(self, now):
        with self.counters_lock:
            for ip, count in self.syn_counts.items():
                if count > self.SEUIL_SYN:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self._block_ip(ip, now, f"SYN Flood ({count} SYN/s)")
            for ip, count in self.udp_counts.items():
                if count > self.SEUIL_UDP:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self._block_ip(ip, now, f"UDP Flood ({count} UDP/s)")
            for ip, count in self.icmp_counts.items():
                if count > self.SEUIL_ICMP:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self._block_ip(ip, now, f"ICMP Flood ({count} ICMP/s)")
            for ip, count in self.ack_counts.items():
                if count > self.SEUIL_ACK:
                    with self.blocked_lock:
                        if ip not in self.blocked_ips:
                            self._block_ip(ip, now, f"ACK Flood ({count} ACK/s)")

    def _block_ip_immediate(self, ip, timestamp, event):
        with self.blocked_lock:
            if ip in self.blocked_ips:
                return

            # Déterminer le type d'attaque pour logging (optionnel)
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

            # Renforcement: si MAC L2 connue dans ce PacketIn, bloquer L2 et ARP
            try:
                mac = str(event.parsed.src)
                if mac:
                    self._block_mac_l2(mac)
                    self._block_arp_from_mac(mac)
                    self.blocked_macs[mac] = (timestamp, f"Reinforced for {ip}")
            except Exception:
                pass

    def _block_ip(self, ip, timestamp, raison):
        log.warning("[ALERTE DDoS] %s détecté de %s - BLOCAGE", raison, ip)

        fm = of.ofp_flow_mod()
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.nw_src = ip
        fm.priority = 2000  # plus haut que forwarding, plus bas que ARP defense
        fm.hard_timeout = self.DUREE_BLOCAGE
        self.connection.send(fm)

        self.blocked_ips[ip] = (timestamp, raison)
        log.info("→ %s bloqué (IP) pour %ds", ip, self.DUREE_BLOCAGE)

    def _block_mac_l2(self, mac):
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
        log.info("→ MAC %s bloquée (L2) pour %ds", mac, self.DUREE_BLOCAGE)

    def _block_arp_from_mac(self, mac):
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
        log.info("→ MAC %s bloquée (ARP) pour %ds", mac, self.DUREE_BLOCAGE)

    def _unblock_expired_ips(self):
        now = time.time()
        with self.blocked_lock:
            expired_ip = [ip for ip, (ts, _) in self.blocked_ips.items() if now - ts > self.DUREE_BLOCAGE]
            for ip in expired_ip:
                raison = self.blocked_ips[ip][1]
                del self.blocked_ips[ip]
                log.info("✓ %s débloqué (timeout expiré - %s)", ip, raison)

            expired_mac = [m for m, (ts, _) in self.blocked_macs.items() if now - ts > self.DUREE_BLOCAGE]
            for m in expired_mac:
                del self.blocked_macs[m]

    def _clear_counters(self):
        self.syn_counts.clear()
        self.udp_counts.clear()
        self.icmp_counts.clear()
        self.ack_counts.clear()

    def _forward_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

def launch():
    def start_switch(event):
        log.info("Connexion switch au firewall multi-couches")
        MultiLayerFirewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("=== Contrôleur Firewall Multi-Couches Démarré ===")
    log.info("Protection contre: SYN/UDP/ICMP/ACK Floods")
