#!/bin/bash

echo "Script wait_and_launch.sh démarré - $(date)" > /tmp/script_log.txt


echo "[+] Starting Open vSwitch..."
service openvswitch-switch start
sleep 2


while ! nc -z 172.18.0.2 6633; do
  sleep 2
done

echo "ok"

tail -f /dev/null
