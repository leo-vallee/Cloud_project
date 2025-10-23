FROM ubuntu:20.04

# Installer dépendances
RUN apt-get update && apt-get install -y python3 git

# Cloner le repo POX juste une fois à la construction
RUN git clone https://github.com/noxrepo/pox.git /pox

# Copier ton script firewall dans l'image
COPY firewall_controller.py /pox/ext/firewall_controller.py
COPY arp.py /pox/ext/arp.py

# Installer autres fichiers/configs si besoin

WORKDIR /pox

# Commande par défaut pour lancer POX avec ton firewall
CMD ["python3", "pox.py", "log.level", "--DEBUG", "arp", "firewall_controller"]
