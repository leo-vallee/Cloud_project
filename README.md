
# Cloud_project


**Année universitaire** : 2025-2026

## 📋 Description

Ce projet implémente une simulation de réseau Software-Defined Networking (SDN) utilisant Mininet pour l'émulation réseau et POX comme contrôleur OpenFlow.

## 🔧 Prérequis

Avant de commencer, assurez-vous d'avoir installé les éléments suivants :

- **Docker** - Pour la containerisation de l'environnement
- **Open vSwitch** - Commutateur virtuel pour SDN
- **Linux** - Système d'exploitation requis (Windows non supporté)
- **Module kernel openvswitch** - Charger avec `sudo modprobe openvswitch`

## 🚀 Installation

Clonez le dépôt Git :

    git clone https://github.com/leo-vallee/Cloud_project.git
    cd Cloud_project

## ▶️ Utilisation

### Méthode 1 : Démarrage automatique (recommandé)

Lancez le script de démarrage complet qui initialise l'environnement et lance les simulations automatiquement :

    ./full_auto_start.sh

### Méthode 2 : Démarrage manuel

Pour un contrôle plus fin, vous pouvez démarrer l'environnement et les attaques séparément :

**Terminal 1** - Démarrer l'environnement Mininet/POX :

    ./start_env.sh

**Terminal 2** - Lancer le script d'attaque :

    ./launch_attack.sh

## 📁 Structure du projet

    Cloud_project/
    ├── start_env.sh          # Script de démarrage de l'environnement (2e méthode)
    ├── launch_attack.sh      # Script de lancement des attaques (2e méthode)
    ├── stop.sh               # Stop les containers
    ├── full_auto_start.sh    # Script de démarrage automatique complet (1er méthode)
    ├── pox-image/            
    │   ├── Dockerfile        # Dockerfile du container pox
    │   ├── arp_detection.py  # Fichier python de détection ARP 
    │   └── ddos_detection.py # Fichier python de détection DOS 
    ├── mininet-image/        
    │   ├── Dockerfile        # Dockerfile du container mininet
    │   ├── attack.py         # Fichier python d'attaque
    └── README.md             # Ce fichier

## 🎥 Démonstration

Une vidéo de démonstration du projet est disponible ici :

<https://youtu.be/vFBTHSI82Ek>

##  Problème

### Erreur lors de l'exécution de `./full_start.sh`

Si vous rencontrez des problèmes D-Bus lors de l'exécution du script complet :

    sudo apt install dbus-x11

### Erreur de module Python (ModuleNotFoundError)

Si vous obtenez une erreur d'importation de module Python :

    sudo apt install python3-setuptools

## 📚 Technologies utilisées

- **Mininet** - Émulateur de réseau pour SDN
- **POX** - Contrôleur OpenFlow en Python
- **Open vSwitch** - Commutateur virtuel multi-couches
- **Docker** - Plateforme de containerisation
- **Python 3.x** - Langage de programmation principal

## 👥 Auteurs

Projet réalisé dans le cadre du Master 2 CDS1 - Cloud Computing

## 🔗 Références

- [Documentation Mininet](http://mininet.org/)
- [Documentation POX](https://noxrepo.github.io/pox-doc/html/)
- [Open vSwitch](https://www.openvswitch.org/)
