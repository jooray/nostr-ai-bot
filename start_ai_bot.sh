#!/bin/bash
# start_ai_bot.sh
# Link Astroport Captain Account to IA auto responder on UPlanet(s)
if [[ -s ~/.zen/Astroport.ONE/tools/my.sh ]]; then
    source ~/.zen/Astroport.ONE/tools/my.sh
else
    echo "Astroport.ONE introuvable : ~/.zen/Astroport.ONE/tools/my.sh"
    exit 1
fi

# Source le fichier secret du Capitaine pour récupérer NSEC
if [[ -s ~/.zen/game/players/.current/secret.nostr ]]; then
    source ~/.zen/game/players/.current/secret.nostr
else
    echo "Fichier secret du Capitaine introuvable : ~/.zen/game/players/.current/secret.nostr"
    exit 1
fi

# Définir la variable d'environnement PRIVATE_KEY avec la clé privée du Capitaine (NSEC)
export PRIVATE_KEY="$NSEC"

# Définir la variable d'environnement RELAYS
[[ "$myRELAY" != "ws://127.0.0.1:7777" ]] \
&& export RELAYS="wss://relay.copylaradio.com,$myRELAY" \
|| export RELAYS="wss://relay.copylaradio.com"

# Définir la variable d'environnement OLLAMA_MODEL
export OLLAMA_MODEL="qwen2.5" # ou le modèle que vous utilisez

# Lancer le script nostr-ai-bot.py
python main.py
