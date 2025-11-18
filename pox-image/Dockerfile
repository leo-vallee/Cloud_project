FROM ubuntu:20.04

# Installer dépendances
RUN apt-get update && apt-get install -y python3 git

# Cloner le repo POX
RUN git clone https://github.com/noxrepo/pox.git /pox

# Copier le script firewall
COPY ddos_detection.py /pox/ext/ddos_detection.py
COPY arp_detection.py /pox/ext/arp_detection.py

WORKDIR /pox

# Commande
CMD ["python3", "pox.py", "log.level", "--DEBUG", "arp_detection", "ddos_detection"]
