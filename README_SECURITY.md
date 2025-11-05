# Guia de Teste de Segurança - Formulário de Login

Este guia contém ferramentas e scripts para testar vulnerabilidades em formulários de login.

## Ferramentas Disponíveis

### 1. Script Python (`security_test.py`)

Script automatizado que testa múltiplas vulnerabilidades:

```bash
# Instalar dependências
pip3 install requests

# Executar teste
python3 security_test.py https://www.reidoslotsinais.com /admin/login
```

**Vulnerabilidades testadas:**
- ✅ SQL Injection
- ✅ Cross-Site Scripting (XSS)
- ✅ CSRF (Cross-Site Request Forgery)
- ✅ Proteção contra Brute Force
- ✅ Política de Senha
- ✅ Exposição de Dados Sensíveis
- ✅ Gerenciamento de Sessão
- ✅ Mensagens de Erro

**Saída:**
- Relatório em JSON (`security_report.json`)
- Resultados no console

### 2. Script Bash Kali Linux (`kali_security_test.sh`)

Usa ferramentas nativas do Kali Linux:

```bash
chmod +x kali_security_test.sh
./kali_security_test.sh
```

**Ferramentas utilizadas:**
- SQLMap (SQL Injection)
- cURL (Requisições HTTP)
- SSLScan (Análise SSL/TLS)

### 3. Arquivo de Payloads (`payloads.txt`)

Coleção de payloads para testes manuais.

## Vulnerabilidades Comuns em Formulários de Login

### 🔴 CRÍTICAS

1. **SQL Injection**
   - Permite bypass de autenticação
   - Pode permitir acesso ao banco de dados
   - Payload: `' OR '1'='1`

2. **Session Hijacking**
   - Cookies sem HttpOnly/Secure
   - Sessões previsíveis

### 🟠 ALTAS

3. **Cross-Site Scripting (XSS)**
   - Roubo de cookies/sessões
   - Redirecionamento malicioso

4. **Falta de HTTPS**
   - Credenciais transmitidas em texto claro

### 🟡 MÉDIAS

5. **CSRF**
   - Ausência de tokens CSRF
   - Permite ações não autorizadas

6. **Brute Force**
   - Sem rate limiting
   - Sem CAPTCHA

### 🟢 BAIXAS

7. **Mensagens de Erro Informativas**
   - Revela se usuário existe
   - Facilita enumeração

## Como Usar

### Teste Rápido

```bash
python3 security_test.py https://www.reidoslotsinais.com /admin/login
```

### Teste Completo com Kali

```bash
# 1. Execute o script Python
python3 security_test.py https://www.reidoslotsinais.com /admin/login

# 2. Execute o script Kali
./kali_security_test.sh

# 3. Analise o relatório
cat security_report.json
```

### Teste Manual com SQLMap

```bash
sqlmap -u "https://www.reidoslotsinais.com/admin/login" \
  --forms \
  --batch \
  --level=3 \
  --risk=2 \
  --dbs
```

## Correções Recomendadas

1. **SQL Injection**: Use prepared statements/parameterized queries
2. **XSS**: Sanitize todas as entradas do usuário
3. **CSRF**: Implemente tokens CSRF
4. **Brute Force**: Rate limiting + CAPTCHA após N tentativas
5. **HTTPS**: Force HTTPS em todo o site
6. **Cookies**: Use HttpOnly e Secure flags
7. **Headers**: Adicione security headers (CSP, X-Frame-Options, etc)

## Aviso Legal

⚠️ **Use apenas em sites que você possui ou tem autorização escrita para testar!**

Testar vulnerabilidades em sites sem autorização é ilegal em muitos países.
