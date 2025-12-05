#!/bin/bash
# Configuration iptables complète pour détection tous types d'attaques

# Créer les chaînes de logging
iptables -N LOG_DROP 2>/dev/null || iptables -F LOG_DROP
iptables -N LOG_ATTACKS 2>/dev/null || iptables -F LOG_ATTACKS

# 1. Logger les paquets TCP suspects (rate limited pour ne pas saturer)
iptables -A INPUT -p tcp -m limit --limit 200/sec --limit-burst 300 \
  -j LOG --log-prefix "IPTABLES DROP: " --log-level 4

# 2. Logger les paquets UDP suspects
iptables -A INPUT -p udp -m limit --limit 300/sec --limit-burst 500 \
  -j LOG --log-prefix "IPTABLES DROP: " --log-level 4

# 3. Logger les paquets ICMP (ping flood)
iptables -A INPUT -p icmp -m limit --limit 100/sec --limit-burst 200 \
  -j LOG --log-prefix "IPTABLES DROP: " --log-level 4

# 4. Logger les connexions invalides
iptables -A INPUT -m state --state INVALID -m limit --limit 50/sec \
  -j LOG --log-prefix "IPTABLES DROP: " --log-level 4

# 5. Logger les scans de ports (nouvelles connexions multiples)
iptables -A INPUT -p tcp -m state --state NEW -m recent --name portscan \
  --set --rsource

iptables -A INPUT -p tcp -m state --state NEW -m recent --name portscan \
  --update --seconds 60 --hitcount 10 --rsource \
  -j LOG --log-prefix "IPTABLES DROP: " --log-level 4
