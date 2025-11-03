FROM iwaseyusuke/mininet

USER root

# Installation de netcat et Python3
RUN apt-get update && \
    apt-get install -y netcat python3 python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copie du script attaque
COPY attack.py /mininet/attack.py
RUN chmod +x /mininet/attack.py
