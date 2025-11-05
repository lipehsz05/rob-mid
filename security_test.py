#!/usr/bin/env python3
"""
Script de Teste de Segurança para Formulário de Login
Testa vulnerabilidades comuns em /admin/login
"""

import requests
import time
from urllib.parse import urljoin
import sys
from colorama import Fore, Style, init

# Inicializar colorama para output colorido
init(autoreset=True)

class SecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.login_url = urljoin(self.base_url, '/admin/login')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.warnings = []
        self.info = []
        
    def print_success(self, message):
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
        
    def print_error(self, message):
        print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")
        
    def print_warning(self, message):
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
        self.warnings.append(message)
        
    def print_info(self, message):
        print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")
        self.info.append(message)
        
    def print_vulnerability(self, message):
        print(f"{Fore.RED}[VULNERABILIDADE] {message}{Style.RESET_ALL}")
        self.vulnerabilities.append(message)
    
    def test_connection(self):
        """Testa se o site está acessível"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Testando: {self.base_url}")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        try:
            response = self.session.get(self.base_url, timeout=10)
            self.print_success(f"Site acessível (Status: {response.status_code})")
            return True
        except requests.exceptions.RequestException as e:
            self.print_error(f"Erro ao conectar: {e}")
            return False
    
    def test_login_page_access(self):
        """Testa acesso à página de login"""
        print(f"\n{Fore.YELLOW}[TESTE 1] Verificando acesso à página de login{Style.RESET_ALL}")
        try:
            response = self.session.get(self.login_url, timeout=10)
            
            if response.status_code == 200:
                self.print_success(f"Página de login acessível: {self.login_url}")
                self.print_info(f"Tamanho da resposta: {len(response.content)} bytes")
                
                # Verificar se há campos de formulário
                if 'input' in response.text.lower() or 'form' in response.text.lower():
                    self.print_success("Formulário encontrado na página")
                else:
                    self.print_warning("Nenhum formulário aparente encontrado")
                    
                return True
            else:
                self.print_error(f"Página retornou status: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.print_error(f"Erro ao acessar página de login: {e}")
            return False
    
    def test_sql_injection(self):
        """Testa SQL Injection no formulário"""
        print(f"\n{Fore.YELLOW}[TESTE 2] Testando SQL Injection{Style.RESET_ALL}")
        
        # Payloads comuns de SQL Injection
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' UNION SELECT NULL--",
            "1' OR '1'='1",
            "admin' OR '1'='1'--",
            "' OR 1=1--",
            "' OR 1=1#",
            "') OR ('1'='1",
        ]
        
        # Tentar identificar os campos do formulário
        try:
            response = self.session.get(self.login_url, timeout=10)
            page_content = response.text.lower()
            
            # Tentar identificar nomes de campos comuns
            possible_fields = []
            if 'name="username"' in page_content or 'id="username"' in page_content:
                possible_fields.append('username')
            if 'name="user"' in page_content or 'id="user"' in page_content:
                possible_fields.append('user')
            if 'name="email"' in page_content or 'id="email"' in page_content:
                possible_fields.append('email')
            if 'name="login"' in page_content or 'id="login"' in page_content:
                possible_fields.append('login')
            if 'name="password"' in page_content or 'id="password"' in page_content:
                possible_fields.append('password')
            if 'name="pass"' in page_content or 'id="pass"' in page_content:
                possible_fields.append('pass')
            
            if not possible_fields:
                possible_fields = ['username', 'user', 'email', 'login']
                password_fields = ['password', 'pass', 'pwd']
            else:
                password_fields = ['password', 'pass', 'pwd']
            
            vulnerable = False
            for payload in sql_payloads[:5]:  # Testar apenas os primeiros 5 para não sobrecarregar
                for user_field in possible_fields:
                    for pass_field in password_fields:
                        data = {
                            user_field: payload,
                            pass_field: payload
                        }
                        
                        try:
                            response = self.session.post(
                                self.login_url,
                                data=data,
                                timeout=10,
                                allow_redirects=False
                            )
                            
                            # Verificar sinais de SQL Injection
                            error_messages = [
                                'sql syntax',
                                'mysql',
                                'postgresql',
                                'database error',
                                'sql error',
                                'warning: mysql',
                                'odbc',
                                'ora-',
                                'microsoft ole db'
                            ]
                            
                            response_text = response.text.lower()
                            if any(error in response_text for error in error_messages):
                                self.print_vulnerability(
                                    f"Possível SQL Injection detectado! "
                                    f"Payload: {payload} | Campo: {user_field}"
                                )
                                vulnerable = True
                                
                        except requests.exceptions.RequestException:
                            continue
                        
                        time.sleep(0.5)  # Delay entre requisições
            
            if not vulnerable:
                self.print_success("Nenhum sinal óbvio de SQL Injection detectado")
                
        except Exception as e:
            self.print_error(f"Erro ao testar SQL Injection: {e}")
    
    def test_xss(self):
        """Testa Cross-Site Scripting (XSS)"""
        print(f"\n{Fore.YELLOW}[TESTE 3] Testando Cross-Site Scripting (XSS){Style.RESET_ALL}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
        ]
        
        try:
            response = self.session.get(self.login_url, timeout=10)
            page_content = response.text.lower()
            
            # Identificar campos
            possible_fields = ['username', 'user', 'email', 'login']
            password_fields = ['password', 'pass']
            
            for payload in xss_payloads[:3]:
                for field in possible_fields:
                    data = {field: payload, 'password': 'test'}
                    
                    try:
                        response = self.session.post(
                            self.login_url,
                            data=data,
                            timeout=10
                        )
                        
                        # Verificar se o payload foi refletido sem sanitização
                        if payload in response.text and '<script' in payload:
                            self.print_vulnerability(
                                f"Possível XSS Refletido detectado! Payload refletido: {payload}"
                            )
                            break
                            
                    except requests.exceptions.RequestException:
                        continue
                    
                    time.sleep(0.5)
            
            self.print_info("XSS testado - verifique manualmente se há payloads refletidos")
            
        except Exception as e:
            self.print_error(f"Erro ao testar XSS: {e}")
    
    def test_csrf_protection(self):
        """Testa proteção contra CSRF"""
        print(f"\n{Fore.YELLOW}[TESTE 4] Verificando proteção CSRF{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.login_url, timeout=10)
            
            # Procurar por tokens CSRF
            csrf_indicators = [
                'csrf',
                'token',
                '_token',
                'authenticity_token',
                'csrf_token',
                'csrfmiddlewaretoken'
            ]
            
            has_csrf = False
            for indicator in csrf_indicators:
                if indicator in response.text.lower():
                    self.print_success(f"Possível token CSRF encontrado: {indicator}")
                    has_csrf = True
                    break
            
            if not has_csrf:
                self.print_vulnerability(
                    "Nenhum token CSRF aparente encontrado! "
                    "O formulário pode ser vulnerável a ataques CSRF."
                )
            else:
                self.print_info("Token CSRF encontrado - proteção pode estar presente")
                
        except Exception as e:
            self.print_error(f"Erro ao verificar CSRF: {e}")
    
    def test_user_enumeration(self):
        """Testa enumeração de usuários"""
        print(f"\n{Fore.YELLOW}[TESTE 5] Testando enumeração de usuários{Style.RESET_ALL}")
        
        test_users = ['admin', 'administrator', 'user', 'test', 'root']
        test_password = 'wrongpassword123'
        
        response_times = []
        error_messages = []
        
        for user in test_users:
            try:
                data = {
                    'username': user,
                    'password': test_password
                }
                
                start_time = time.time()
                response = self.session.post(
                    self.login_url,
                    data=data,
                    timeout=10,
                    allow_redirects=False
                )
                response_time = time.time() - start_time
                response_times.append((user, response_time))
                
                # Verificar diferenças nas mensagens de erro
                if response.status_code in [200, 401, 403]:
                    error_messages.append((user, response.text[:200]))
                
                time.sleep(1)  # Delay maior para evitar rate limiting
                
            except requests.exceptions.RequestException as e:
                self.print_error(f"Erro ao testar usuário {user}: {e}")
        
        # Analisar diferenças
        if len(set([msg[1] for msg in error_messages])) > 1:
            self.print_vulnerability(
                "Possível enumeração de usuários detectada! "
                "Diferentes mensagens de erro para diferentes usuários."
            )
        
        self.print_info("Enumeração de usuários testada")
    
    def test_rate_limiting(self):
        """Testa se há rate limiting/proteção contra brute force"""
        print(f"\n{Fore.YELLOW}[TESTE 6] Verificando proteção contra brute force{Style.RESET_ALL}")
        
        try:
            # Tentar múltiplas requisições rápidas
            attempts = 10
            blocked = False
            
            for i in range(attempts):
                data = {
                    'username': 'test',
                    'password': f'wrongpass{i}'
                }
                
                response = self.session.post(
                    self.login_url,
                    data=data,
                    timeout=10,
                    allow_redirects=False
                )
                
                # Verificar se foi bloqueado
                if response.status_code == 429:  # Too Many Requests
                    self.print_success("Rate limiting detectado (Status 429)")
                    blocked = True
                    break
                elif 'blocked' in response.text.lower() or 'too many' in response.text.lower():
                    self.print_success("Proteção contra brute force detectada")
                    blocked = True
                    break
                
                time.sleep(0.3)
            
            if not blocked:
                self.print_vulnerability(
                    f"Nenhuma proteção aparente contra brute force detectada "
                    f"após {attempts} tentativas!"
                )
            
        except Exception as e:
            self.print_error(f"Erro ao testar rate limiting: {e}")
    
    def test_https_configuration(self):
        """Testa configuração HTTPS"""
        print(f"\n{Fore.YELLOW}[TESTE 7] Verificando configuração HTTPS{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=True)
            
            if response.url.startswith('https://'):
                self.print_success("HTTPS configurado corretamente")
            else:
                self.print_warning("Site não está usando HTTPS")
            
            # Verificar redirecionamento HTTP -> HTTPS
            http_url = self.base_url.replace('https://', 'http://')
            try:
                http_response = requests.get(http_url, timeout=5, allow_redirects=False)
                if http_response.status_code in [301, 302, 307, 308]:
                    if http_response.headers.get('Location', '').startswith('https://'):
                        self.print_success("Redirecionamento HTTP -> HTTPS configurado")
                    else:
                        self.print_warning("Redirecionamento HTTP não aponta para HTTPS")
                else:
                    self.print_warning("Site acessível via HTTP sem redirecionamento")
            except:
                pass
                
        except requests.exceptions.SSLError as e:
            self.print_warning(f"Problema com certificado SSL: {e}")
        except Exception as e:
            self.print_error(f"Erro ao verificar HTTPS: {e}")
    
    def test_information_disclosure(self):
        """Testa exposição de informações sensíveis"""
        print(f"\n{Fore.YELLOW}[TESTE 8] Verificando exposição de informações{Style.RESET_ALL}")
        
        try:
            response = self.session.get(self.login_url, timeout=10)
            
            # Verificar informações que não deveriam ser expostas
            sensitive_info = {
                'versão do servidor': ['apache/', 'nginx/', 'iis/', 'server:'],
                'versão do php': ['php/', 'x-powered-by: php'],
                'versão do framework': ['django/', 'laravel/', 'rails/', 'symfony/'],
                'stack trace': ['stack trace', 'traceback', 'exception'],
                'caminhos do sistema': ['/var/www/', 'c:\\windows\\', '/home/'],
                'informações de debug': ['debug mode', 'debug=true'],
            }
            
            response_headers = str(response.headers).lower()
            response_text = response.text.lower()
            
            for info_type, patterns in sensitive_info.items():
                for pattern in patterns:
                    if pattern in response_headers or pattern in response_text:
                        self.print_warning(
                            f"Possível exposição de {info_type} detectada: {pattern}"
                        )
            
            self.print_info("Verificação de informações sensíveis concluída")
            
        except Exception as e:
            self.print_error(f"Erro ao verificar informações: {e}")
    
    def generate_report(self):
        """Gera relatório final"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"RELATÓRIO DE SEGURANÇA")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        if self.vulnerabilities:
            print(f"{Fore.RED}VULNERABILIDADES ENCONTRADAS: {len(self.vulnerabilities)}{Style.RESET_ALL}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"  {i}. {vuln}")
        else:
            print(f"{Fore.GREEN}Nenhuma vulnerabilidade crítica detectada automaticamente{Style.RESET_ALL}")
        
        if self.warnings:
            print(f"\n{Fore.YELLOW}AVISOS: {len(self.warnings)}{Style.RESET_ALL}")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")
        
        print(f"\n{Fore.CYAN}NOTA: Este é um teste automatizado básico.{Style.RESET_ALL}")
        print("Para uma análise completa, recomenda-se:")
        print("  - Teste manual com Burp Suite ou OWASP ZAP")
        print("  - Análise de código fonte")
        print("  - Teste de penetração profissional")
        print()
    
    def run_all_tests(self):
        """Executa todos os testes"""
        if not self.test_connection():
            return
        
        self.test_login_page_access()
        self.test_sql_injection()
        self.test_xss()
        self.test_csrf_protection()
        self.test_user_enumeration()
        self.test_rate_limiting()
        self.test_https_configuration()
        self.test_information_disclosure()
        
        self.generate_report()


def main():
    print(f"{Fore.CYAN}")
    print("="*60)
    print("  TESTE DE SEGURANÇA - FORMULÁRIO DE LOGIN")
    print("="*60)
    print(f"{Style.RESET_ALL}")
    
    # URL do site
    base_url = "https://www.reidoslotsinais.com"
    
    tester = SecurityTester(base_url)
    tester.run_all_tests()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Teste interrompido pelo usuário{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Erro fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)
