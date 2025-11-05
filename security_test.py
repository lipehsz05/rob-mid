#!/usr/bin/env python3
"""
Script de Teste de Segurança para Formulário de Login
Testa vulnerabilidades comuns em formulários web
"""

import requests
import sys
import time
from urllib.parse import urljoin
from datetime import datetime
import json

class SecurityTester:
    def __init__(self, base_url, login_path="/admin/login"):
        self.base_url = base_url.rstrip('/')
        self.login_url = urljoin(self.base_url, login_path)
        self.session = requests.Session()
        self.results = {
            'url': self.login_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': []
        }
        
    def log_vulnerability(self, vuln_type, severity, description, evidence=""):
        """Registra uma vulnerabilidade encontrada"""
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        }
        self.results['vulnerabilities'].append(vuln)
        print(f"\n[!] VULNERABILIDADE ENCONTRADA: {vuln_type}")
        print(f"    Severidade: {severity}")
        print(f"    Descrição: {description}")
        if evidence:
            print(f"    Evidência: {evidence}")
    
    def test_sql_injection(self):
        """Testa vulnerabilidades de SQL Injection"""
        print("\n[*] Testando SQL Injection...")
        
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' OR '1'='1",
            "' OR 'x'='x",
            "admin' OR '1'='1",
            "' OR 1=1#",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "1' OR '1'='1'--",
            "' OR '1'='1' LIMIT 1--",
        ]
        
        for payload in sql_payloads:
            try:
                data = {
                    'username': payload,
                    'password': 'test'
                }
                response = self.session.post(self.login_url, data=data, timeout=10, allow_redirects=False)
                
                # Verifica sinais de SQL Injection
                if response.status_code == 302:  # Redirect pode indicar login bem-sucedido
                    self.log_vulnerability(
                        "SQL Injection",
                        "CRÍTICA",
                        f"Possível SQL Injection detectado com payload: {payload}",
                        f"Status: {response.status_code}, Redirect para: {response.headers.get('Location', 'N/A')}"
                    )
                    return True
                    
                # Verifica mensagens de erro SQL
                error_indicators = [
                    'sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-',
                    'sql error', 'database error', 'syntax error'
                ]
                response_text = response.text.lower()
                for indicator in error_indicators:
                    if indicator in response_text:
                        self.log_vulnerability(
                            "SQL Injection - Informação Exposta",
                            "ALTA",
                            f"Mensagem de erro SQL exposta com payload: {payload}",
                            f"Erro detectado: {indicator}"
                        )
                        return True
                        
            except Exception as e:
                print(f"    [-] Erro ao testar payload {payload}: {e}")
                
        print("    [+] Nenhuma vulnerabilidade de SQL Injection aparente")
        return False
    
    def test_xss(self):
        """Testa vulnerabilidades de Cross-Site Scripting (XSS)"""
        print("\n[*] Testando Cross-Site Scripting (XSS)...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
        ]
        
        for payload in xss_payloads:
            try:
                data = {
                    'username': payload,
                    'password': 'test'
                }
                response = self.session.post(self.login_url, data=data, timeout=10)
                
                # Verifica se o payload foi refletido sem sanitização
                if payload in response.text:
                    self.log_vulnerability(
                        "Cross-Site Scripting (XSS)",
                        "ALTA",
                        f"Possível XSS detectado. Payload refletido na resposta: {payload[:50]}...",
                        f"Payload completo: {payload}"
                    )
                    return True
                    
            except Exception as e:
                print(f"    [-] Erro ao testar payload XSS {payload}: {e}")
                
        print("    [+] Nenhuma vulnerabilidade de XSS aparente")
        return False
    
    def test_csrf(self):
        """Testa proteção contra CSRF"""
        print("\n[*] Testando proteção CSRF...")
        
        try:
            # Primeiro, obtém a página de login
            response = self.session.get(self.login_url, timeout=10)
            
            # Verifica se há token CSRF
            csrf_indicators = ['csrf', '_token', 'authenticity_token', 'csrf_token', 'csrfmiddlewaretoken']
            has_csrf = False
            
            for indicator in csrf_indicators:
                if indicator in response.text.lower():
                    has_csrf = True
                    break
            
            if not has_csrf:
                self.log_vulnerability(
                    "CSRF - Falta de Proteção",
                    "MÉDIA",
                    "Nenhum token CSRF detectado no formulário",
                    "O formulário pode ser vulnerável a ataques CSRF"
                )
                return True
            else:
                print("    [+] Token CSRF detectado no formulário")
                
        except Exception as e:
            print(f"    [-] Erro ao testar CSRF: {e}")
            
        return False
    
    def test_brute_force_protection(self):
        """Testa proteção contra brute force"""
        print("\n[*] Testando proteção contra Brute Force...")
        
        try:
            # Tenta múltiplas requisições rápidas
            rate_limit_triggered = False
            blocked_after = None
            
            for i in range(10):
                data = {
                    'username': f'test{i}',
                    'password': 'wrongpassword'
                }
                response = self.session.post(self.login_url, data=data, timeout=10, allow_redirects=False)
                
                # Verifica se há rate limiting
                if response.status_code == 429:  # Too Many Requests
                    rate_limit_triggered = True
                    blocked_after = i + 1
                    break
                    
                # Verifica se há CAPTCHA
                if 'captcha' in response.text.lower() or 'recaptcha' in response.text.lower():
                    print("    [+] CAPTCHA detectado - boa proteção")
                    return False
                    
                time.sleep(0.5)  # Pequeno delay entre requisições
            
            if not rate_limit_triggered:
                self.log_vulnerability(
                    "Brute Force - Falta de Proteção",
                    "MÉDIA",
                    "Nenhuma proteção contra brute force detectada",
                    f"Conseguiu fazer {i+1} tentativas sem bloqueio"
                )
                return True
            else:
                print(f"    [+] Rate limiting detectado após {blocked_after} tentativas")
                
        except Exception as e:
            print(f"    [-] Erro ao testar brute force: {e}")
            
        return False
    
    def test_password_policy(self):
        """Testa políticas de senha"""
        print("\n[*] Testando políticas de senha...")
        
        weak_passwords = ['123456', 'password', 'admin', '123', 'qwerty']
        
        try:
            for weak_pwd in weak_passwords:
                data = {
                    'username': 'test',
                    'password': weak_pwd
                }
                response = self.session.post(self.login_url, data=data, timeout=10, allow_redirects=False)
                
                # Se aceitar senha muito fraca, pode ser vulnerável
                if response.status_code == 200:
                    # Verifica se há validação de senha forte
                    if 'senha forte' not in response.text.lower() and 'strong password' not in response.text.lower():
                        if weak_pwd == weak_passwords[0]:  # Só reporta uma vez
                            self.log_vulnerability(
                                "Política de Senha Fraca",
                                "BAIXA",
                                "Sistema pode aceitar senhas fracas",
                                "Não há validação aparente de força de senha"
                            )
                            return True
                            
        except Exception as e:
            print(f"    [-] Erro ao testar política de senha: {e}")
            
        print("    [+] Teste de política de senha concluído")
        return False
    
    def test_sensitive_data_exposure(self):
        """Testa exposição de dados sensíveis"""
        print("\n[*] Testando exposição de dados sensíveis...")
        
        try:
            response = self.session.get(self.login_url, timeout=10)
            
            # Verifica headers de segurança
            security_headers = {
                'X-Frame-Options': 'Proteção contra clickjacking',
                'X-Content-Type-Options': 'Proteção contra MIME sniffing',
                'Strict-Transport-Security': 'Força HTTPS',
                'Content-Security-Policy': 'Proteção contra XSS',
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers:
                self.log_vulnerability(
                    "Headers de Segurança Ausentes",
                    "MÉDIA",
                    "Faltam headers de segurança importantes",
                    f"Headers ausentes: {', '.join(missing_headers)}"
                )
            
            # Verifica se é HTTPS
            if not self.login_url.startswith('https'):
                self.log_vulnerability(
                    "Conexão Não Criptografada",
                    "ALTA",
                    "Login não está usando HTTPS",
                    "Credenciais podem ser interceptadas"
                )
                return True
            else:
                print("    [+] HTTPS está sendo usado")
                
        except Exception as e:
            print(f"    [-] Erro ao testar exposição de dados: {e}")
            
        return False
    
    def test_session_management(self):
        """Testa gerenciamento de sessão"""
        print("\n[*] Testando gerenciamento de sessão...")
        
        try:
            response = self.session.post(
                self.login_url,
                data={'username': 'test', 'password': 'test'},
                timeout=10,
                allow_redirects=False
            )
            
            # Verifica cookies de sessão
            cookies = response.cookies
            session_cookies = [c for c in cookies if 'session' in c.name.lower() or 'auth' in c.name.lower()]
            
            for cookie in session_cookies:
                issues = []
                
                if not cookie.secure:
                    issues.append("flag Secure ausente")
                    
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("flag HttpOnly ausente")
                
                if issues:
                    self.log_vulnerability(
                        "Cookie de Sessão Inseguro",
                        "ALTA",
                        f"Cookie {cookie.name} tem problemas de segurança",
                        f"Problemas: {', '.join(issues)}"
                    )
                    return True
                    
            print("    [+] Cookies de sessão parecem seguros")
            
        except Exception as e:
            print(f"    [-] Erro ao testar sessão: {e}")
            
        return False
    
    def test_error_messages(self):
        """Testa mensagens de erro que podem vazar informações"""
        print("\n[*] Testando mensagens de erro...")
        
        try:
            # Testa com usuário inexistente
            data = {
                'username': 'usuario_inexistente_12345',
                'password': 'qualquer_senha'
            }
            response = self.session.post(self.login_url, data=data, timeout=10)
            
            # Verifica se a mensagem de erro revela informações
            error_messages = [
                'usuário não existe',
                'user not found',
                'invalid username',
                'invalid user',
                'usuário inválido'
            ]
            
            response_lower = response.text.lower()
            for error_msg in error_messages:
                if error_msg in response_lower:
                    self.log_vulnerability(
                        "Vazamento de Informação",
                        "BAIXA",
                        "Mensagem de erro revela se usuário existe ou não",
                        f"Mensagem detectada: {error_msg}"
                    )
                    return True
            
            print("    [+] Mensagens de erro não revelam informações sensíveis")
            
        except Exception as e:
            print(f"    [-] Erro ao testar mensagens de erro: {e}")
            
        return False
    
    def run_all_tests(self):
        """Executa todos os testes"""
        print(f"\n{'='*60}")
        print(f"TESTE DE SEGURANÇA - {self.login_url}")
        print(f"{'='*60}")
        
        tests = [
            ("SQL Injection", self.test_sql_injection),
            ("XSS", self.test_xss),
            ("CSRF", self.test_csrf),
            ("Brute Force", self.test_brute_force_protection),
            ("Política de Senha", self.test_password_policy),
            ("Exposição de Dados", self.test_sensitive_data_exposure),
            ("Gerenciamento de Sessão", self.test_session_management),
            ("Mensagens de Erro", self.test_error_messages),
        ]
        
        for test_name, test_func in tests:
            try:
                test_func()
            except Exception as e:
                print(f"\n[!] Erro ao executar teste {test_name}: {e}")
        
        return self.results
    
    def save_report(self, filename="security_report.json"):
        """Salva o relatório em JSON"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Relatório salvo em {filename}")


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 security_test.py <url_base> [caminho_login]")
        print("Exemplo: python3 security_test.py https://www.reidoslotsinais.com /admin/login")
        sys.exit(1)
    
    base_url = sys.argv[1]
    login_path = sys.argv[2] if len(sys.argv) > 2 else "/admin/login"
    
    tester = SecurityTester(base_url, login_path)
    results = tester.run_all_tests()
    
    # Resumo
    print(f"\n{'='*60}")
    print("RESUMO DOS TESTES")
    print(f"{'='*60}")
    print(f"Total de vulnerabilidades encontradas: {len(results['vulnerabilities'])}")
    
    if results['vulnerabilities']:
        print("\nVulnerabilidades por severidade:")
        severities = {}
        for vuln in results['vulnerabilities']:
            sev = vuln['severity']
            severities[sev] = severities.get(sev, 0) + 1
        
        for sev, count in sorted(severities.items(), key=lambda x: ['CRÍTICA', 'ALTA', 'MÉDIA', 'BAIXA'].index(x[0]) if x[0] in ['CRÍTICA', 'ALTA', 'MÉDIA', 'BAIXA'] else 99):
            print(f"  {sev}: {count}")
    else:
        print("\n[+] Nenhuma vulnerabilidade crítica encontrada!")
    
    tester.save_report()
    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
