FROM iwaseyusuke/mininet

USER root

# Installation de netcat et Python3
RUN apt-get update && \
    apt-get install -y netcat python3 python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copie du script Mininet dans l'image
COPY wait_and_launch.sh /mininet/wait_and_launch.sh
RUN chmod +x /mininet/wait_and_launch.sh

# Copie du script attaque
COPY arp_attack.py /mininet/arp_attack.py
RUN chmod +x /mininet/arp_attack.py

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["bash /mininet/wait_and_launch.sh"]
