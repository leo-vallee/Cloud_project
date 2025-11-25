from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr
from collections import defaultdict
import time
import threading

log = core.getLogger()

class ARPDefenseFirewall(object):
    MAX_IPS_PER_MAC = 1
    FENETRE_TEMPS = 400.0
    DUREE_BLOCAGE = 10

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Firewall [ARP] connecté au switch %s", connection)

        self.ip_mac_table = {}               
        self.mac_ip_set = defaultdict(set)  
        self.blocked_macs = {}               

        self.last_reset = time.time()
        self.lock = threading.Lock()

    def _handle_PacketIn(self, event):

        try:
            packet = event.parsed
            if not packet or not packet.parsed:
                return
        except AttributeError as e:
            return

        self._unblock_expired()

        if packet.type != ethernet.ARP_TYPE:
            src_mac_l2 = str(packet.src)
            if src_mac_l2 in self.blocked_macs:
                log.debug("DROP non-ARP de MAC bloquée %s", src_mac_l2)
                return
            self._forward_packet(event)
            return

        arp_pkt = packet.payload
        src_ip = str(arp_pkt.protosrc)
        src_mac = str(arp_pkt.hwsrc)

        # log.debug("ARP reçu: src_ip=%s src_mac=%s", src_ip, src_mac)

        with self.lock:
            if src_mac in self.blocked_macs:
                self._block_mac_immediate(src_mac, "Déjà bloquée - renforcement")
                return

            # Détection ARP Spoofing (IP -> MAC change)
            if src_ip in self.ip_mac_table:
                old_mac = self.ip_mac_table[src_ip]
                if old_mac != src_mac:
                    log.warning("[ALERTE ARP SPOOFING] IP %s: %s -> %s", src_ip, old_mac, src_mac)
                    self._block_mac_immediate(src_mac, "IP hijacking %s" % src_ip)
                    return

            # Détection ARP Flood (MAC -> plusieurs IPs)
            self.mac_ip_set[src_mac].add(src_ip)
            if len(self.mac_ip_set[src_mac]) > self.MAX_IPS_PER_MAC:
                log.warning("[ALERTE ARP FLOOD] MAC %s: IPs=%s", src_mac, list(self.mac_ip_set[src_mac]))
                self._block_mac_immediate(src_mac, "ARP flood multi-IP")
                self.mac_ip_set[src_mac].remove(src_ip)
                return

            
            self.ip_mac_table[src_ip] = src_mac

        
        self._forward_packet(event)

        now = time.time()
        if now - self.last_reset > self.FENETRE_TEMPS:
            log.info("Fenêtre atteinte, maintien des tables (pas de purge agressive).")
            self.last_reset = now

    def _block_mac_immediate(self, mac, raison):
        # Drop ARP de cette MAC (hautement prioritaire)
        try:
            ea = EthAddr(mac)
        except Exception:
            log.error("EthAddr invalide pour %s", mac)
            return

        fm_arp = of.ofp_flow_mod()
        fm_arp.match.dl_type = ethernet.ARP_TYPE
        fm_arp.match.dl_src = ea
        fm_arp.priority = 3000
        fm_arp.hard_timeout = self.DUREE_BLOCAGE
        self.connection.send(fm_arp)

        # Drop tout trafic L2 (tous types) de cette MAC
        fm_l2 = of.ofp_flow_mod()
        fm_l2.match.dl_src = ea
        fm_l2.priority = 2900
        fm_l2.hard_timeout = self.DUREE_BLOCAGE
        self.connection.send(fm_l2)

        self.blocked_macs[mac] = (time.time(), raison)
        log.info("MAC %s bloquée (ARP+L2) pour %ds (%s)", mac, self.DUREE_BLOCAGE, raison)

    def _unblock_expired(self):
        now = time.time()
        expired = [m for m, (ts, _) in self.blocked_macs.items() if now - ts > self.DUREE_BLOCAGE]
        for m in expired:
            raison = self.blocked_macs[m][1]
            del self.blocked_macs[m]
            log.info("MAC %s débloquée (timeout expiré - %s)", m, raison)

    def _forward_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

def launch():
    def start(event):
        ARPDefenseFirewall(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start)
    log.info("=== Contrôleur POX ARP Defense démarré ===")
