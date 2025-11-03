#!/bin/bash

echo "Démarrage de l'environnement..."
docker-compose up -d --build

echo "Attente du démarrage des containers..."
sleep 5

# Obtenir le chemin absolu du répertoire du script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH_SCRIPT="$SCRIPT_DIR/launch_attack.sh"

echo "Ouverture automatique du GUI d'attaque dans un nouveau terminal..."

# Fonction pour détecter et ouvrir un terminal
open_terminal_with_attack() {
    # Essayer différents terminaux dans l'ordre
    if command -v x-terminal-emulator &> /dev/null; then
        x-terminal-emulator -e bash -c "$LAUNCH_SCRIPT; echo ''; read -p 'Appuyez sur Entrée pour fermer...'" &
    elif command -v gnome-terminal &> /dev/null; then
        gnome-terminal -- bash -c "$LAUNCH_SCRIPT; echo ''; read -p 'Appuyez sur Entrée pour fermer...'" &
    elif command -v konsole &> /dev/null; then
        konsole -e bash -c "$LAUNCH_SCRIPT; echo ''; read -p 'Appuyez sur Entrée pour fermer...'" &
    elif command -v xfce4-terminal &> /dev/null; then
        xfce4-terminal -e bash -c "$LAUNCH_SCRIPT; echo ''; read -p 'Appuyez sur Entrée pour fermer...'" &
    elif command -v xterm &> /dev/null; then
        xterm -e bash -c "$LAUNCH_SCRIPT; echo ''; read -p 'Appuyez sur Entrée pour fermer...'" &
    elif command -v terminator &> /dev/null; then
        terminator -e bash -c "$LAUNCH_SCRIPT; echo ''; read -p 'Appuyez sur Entrée pour fermer...'" &
    elif command -v kitty &> /dev/null; then
        kitty bash -c "$LAUNCH_SCRIPT; echo ''; read -p 'Appuyez sur Entrée pour fermer...'" &
    else
        echo "Aucun terminal graphique détecté."
        echo "Lance manuellement: ./launch_attack.sh"
        return 1
    fi
    return 0
}


if open_terminal_with_attack; then
    echo "Terminal d'attaque ouvert !"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Logs POX ci-dessous (Ctrl+C pour arrêter)"
echo "════════════════════════════════════════════════════════"
echo ""

# Affiche les logs POX dans le terminal actuel
docker logs -f pox

# Cleanup à l'arrêt
echo ""
echo "Arrêt de l'environnement..."
docker-compose down