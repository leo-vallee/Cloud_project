FROM ubuntu:20.04

# Installer dépendances
RUN apt-get update && apt-get install -y python3 git

# Cloner le repo POX juste une fois à la construction
RUN git clone https://github.com/noxrepo/pox.git /pox

# Copier ton script firewall dans l'image
COPY ddos_detection.py /pox/ext/ddos_detection.py
COPY arp_detection.py /pox/ext/arp_detection.py

# Installer autres fichiers/configs si besoin

WORKDIR /pox

# Commande par défaut pour lancer POX avec ton firewall
CMD ["python3", "pox.py", "log.level", "--DEBUG", "arp_detection", "ddos_detection"]
