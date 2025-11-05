# Guia de Teste de Segurança - Formulário de Login

Este guia contém ferramentas e scripts para testar vulnerabilidades no formulário de login do site **https://www.reidoslotsinais.com/admin/login**

## 📋 Pré-requisitos

### Instalar dependências Python
```bash
pip3 install -r requirements.txt
```

### Ferramentas do Kali Linux (já instaladas)
- Burp Suite
- OWASP ZAP
- SQLMap
- Nikto
- Nmap
- Hydra

## 🚀 Como Usar

### 1. Teste Automatizado com Python

Execute o script Python que testa várias vulnerabilidades automaticamente:

```bash
python3 security_test.py
```

O script testa:
- ✅ Acessibilidade do site
- ✅ SQL Injection
- ✅ Cross-Site Scripting (XSS)
- ✅ Proteção CSRF
- ✅ Enumeração de usuários
- ✅ Rate limiting / Proteção contra brute force
- ✅ Configuração HTTPS
- ✅ Exposição de informações sensíveis

### 2. Teste Manual com Burp Suite (RECOMENDADO)

1. **Iniciar o Burp Suite**
   ```bash
   burpsuite
   ```

2. **Configurar Proxy no Navegador**
   - Firefox: Settings → Network Settings → Manual proxy → 127.0.0.1:8080
   - Chrome: Extensão Proxy SwitchyOmega ou argumentos de linha de comando

3. **Passos para teste completo:**
   - Navegue até `https://www.reidoslotsinais.com/admin/login`
   - Intercepte a requisição POST no Burp Proxy
   - Envie para o Burp Scanner (análise automática)
   - Use o Burp Intruder para:
     - Teste de força bruta
     - Teste de SQL Injection automatizado
     - Enumeração de usuários

4. **Verificar resultados:**
   - Vá em "Issues" para ver vulnerabilidades encontradas
   - Analise cada vulnerabilidade reportada

### 3. Teste com SQLMap

```bash
# Modo básico (formulário)
sqlmap -u "https://www.reidoslotsinais.com/admin/login" --forms --batch

# Modo avançado (com requisição capturada)
# 1. Capture a requisição POST com Burp Suite
# 2. Salve em um arquivo request.txt
sqlmap -r request.txt --batch --dbs
```

### 4. Teste com OWASP ZAP

**Interface Gráfica:**
```bash
zaproxy
```

**Linha de Comando:**
```bash
zap-cli quick-scan --self-contained https://www.reidoslotsinais.com
```

### 5. Verificar Headers e Configuração

```bash
# Headers HTTP
curl -I https://www.reidoslotsinais.com/admin/login

# Teste de SSL/TLS
sslscan www.reidoslotsinais.com
```

### 6. Teste de Rate Limiting

```bash
# Script rápido para testar proteção contra brute force
for i in {1..20}; do 
  curl -X POST https://www.reidoslotsinais.com/admin/login \
    -d "username=test&password=test$i" \
    -w "Tentativa $i: %{http_code}\n" \
    -o /dev/null -s
  sleep 0.5
done
```

## 🔍 Vulnerabilidades Comuns a Verificar

### 1. SQL Injection
- **Sintoma:** Mensagens de erro do banco de dados
- **Teste:** Payloads como `' OR '1'='1`, `admin'--`
- **Impacto:** Acesso não autorizado ao banco de dados

### 2. Cross-Site Scripting (XSS)
- **Sintoma:** Scripts executando no navegador
- **Teste:** Payloads como `<script>alert('XSS')</script>`
- **Impacto:** Roubo de sessão, phishing

### 3. CSRF (Cross-Site Request Forgery)
- **Sintoma:** Ausência de token CSRF
- **Teste:** Verificar se há token no formulário
- **Impacto:** Ações não autorizadas em nome do usuário

### 4. Enumeração de Usuários
- **Sintoma:** Mensagens de erro diferentes para usuários existentes/inexistentes
- **Teste:** Tentar login com vários usuários e comparar respostas
- **Impacto:** Descoberta de usuários válidos

### 5. Brute Force
- **Sintoma:** Ausência de rate limiting ou CAPTCHA
- **Teste:** Múltiplas tentativas de login
- **Impacto:** Quebra de senhas por força bruta

### 6. Autenticação Fraca
- **Sintoma:** Senhas simples, sem política de complexidade
- **Teste:** Tentar senhas comuns (admin, 123456, password)
- **Impacto:** Acesso fácil a contas

### 7. Exposição de Informações
- **Sintoma:** Versões de software, stack traces, caminhos de sistema
- **Teste:** Verificar headers HTTP e mensagens de erro
- **Impacto:** Facilitar ataques direcionados

## 📊 Checklist de Segurança

- [ ] SQL Injection protegido (prepared statements)
- [ ] XSS protegido (sanitização de input)
- [ ] CSRF token presente e validado
- [ ] Rate limiting implementado
- [ ] CAPTCHA ou 2FA implementado
- [ ] Mensagens de erro genéricas (sem enumeração)
- [ ] HTTPS configurado corretamente
- [ ] Senhas com hash forte (bcrypt, argon2)
- [ ] Sessões seguras (HttpOnly, Secure flags)
- [ ] Logs de tentativas de login
- [ ] Bloqueio de conta após tentativas falhas
- [ ] Headers de segurança (HSTS, CSP, X-Frame-Options)

## ⚠️ Avisos Importantes

1. **Use apenas em sites que você possui ou tem autorização escrita**
2. **Alguns testes podem ser detectados como ataques e bloquear seu IP**
3. **Testes de força bruta podem sobrecarregar o servidor**
4. **Sempre faça backup antes de testes em produção**
5. **Considere contratar um profissional de segurança para testes completos**

## 📚 Recursos Adicionais

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## 🔧 Solução de Problemas

### Erro: "ModuleNotFoundError: No module named 'colorama'"
```bash
pip3 install -r requirements.txt
```

### Erro de conexão SSL
```bash
# Desabilitar verificação SSL (apenas para testes)
export PYTHONHTTPSVERIFY=0
```

### Burp Suite não intercepta requisições
- Verifique se o proxy está configurado corretamente
- Certifique-se de que o certificado CA do Burp está instalado

## 📝 Relatório de Testes

Após executar os testes, documente:
1. Vulnerabilidades encontradas
2. Nível de severidade (Crítica, Alta, Média, Baixa)
3. Evidências (screenshots, logs)
4. Recomendações de correção
5. Priorização das correções

---

**Última atualização:** 2024
