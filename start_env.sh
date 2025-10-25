#!/bin/bash
echo "Démarrage de l'environnement Docker..."
docker-compose up -d
echo "Attente du démarrage des containers (5s)..."
sleep 5
echo ""
echo "════════════════════════════════════════════════════════"
echo "Environnement démarré !"
echo "Logs POX ci-dessous (Ctrl+C pour arrêter)"
echo "════════════════════════════════════════════════════════"
echo "OUVRE UN AUTRE TERMINAL et lance: ./launch_attack.sh"
echo "════════════════════════════════════════════════════════"
echo ""
docker logs -f pox
