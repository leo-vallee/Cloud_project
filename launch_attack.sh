#!/bin/bash
echo "Lancement de l'interface d'attaque..."
if ! docker ps | grep -q mininet; then
    echo "Le container mininet n'est pas lancé !"
    echo "Lance d'abord: ./start_env.sh"
    exit 1
fi
docker exec -it mininet python3 /mininet/arp_attack.py
