# 🚀 Guia Rápido - Teste de Segurança

## Opção 1: Teste Automatizado (Mais Rápido)

```bash
python3 security_test.py
```

Este comando vai testar automaticamente:
- SQL Injection
- XSS
- CSRF
- Enumeração de usuários
- Rate limiting
- E mais...

## Opção 2: Teste Manual com Burp Suite (Mais Completo)

1. Abra o Burp Suite:
   ```bash
   burpsuite
   ```

2. Configure o proxy no navegador (127.0.0.1:8080)

3. Acesse: https://www.reidoslotsinais.com/admin/login

4. No Burp Suite:
   - Proxy → Intercept está ON
   - Faça login
   - Clique com botão direito na requisição → "Send to Scanner"
   - Vá em "Scanner" e veja os resultados

## Opção 3: Ver Comandos do Kali

```bash
bash kali_commands.sh
```

Isso mostra todos os comandos úteis do Kali Linux para teste de segurança.

## 📋 Checklist Rápido

Após os testes, verifique:
- [ ] Há proteção contra SQL Injection?
- [ ] Há token CSRF no formulário?
- [ ] Há rate limiting (proteção contra brute force)?
- [ ] Mensagens de erro são genéricas?
- [ ] HTTPS está configurado corretamente?

---

**Para mais detalhes, veja:** README_SECURITY.md
