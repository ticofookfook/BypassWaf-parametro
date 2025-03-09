# WAF Bypass Tester

Uma ferramenta avançada para testar e identificar possíveis métodos de bypass em Web Application Firewalls (WAFs).

## Características

- Teste sistemático de parâmetros comuns em aplicações web
- Ampla biblioteca de payloads para tentativas de bypass de WAF
- Detecção inteligente de bloqueios e falsos positivos
- Suporte a requisições GET e POST
- Análise de similaridade para identificar respostas realmente diferentes
- Execução paralela para testes mais rápidos
- Modo rápido para resultados preliminares

## Instalação

```bash
# Clonar o repositório ou baixar o script
git clone https://github.com/seu-usuario/waf-bypass-tester.git
cd waf-bypass-tester

# Instalar dependências
pip install requests colorama
```

## Uso

### Uso básico

```bash
python waf-bypass-tester.py https://example.com/login.jsp
```

### Opções disponíveis

```bash
python waf-bypass-tester.py -h
```

Saída:
```
usage: waf-bypass-tester.py [-h] [--threads THREADS] [--timeout TIMEOUT] [--quick] [--output OUTPUT] url

Testador de bypass de WAF para aplicações web

positional arguments:
  url                  URL completa do endpoint a ser testado (ex: https://example.com/login.jsp)

optional arguments:
  -h, --help           show this help message and exit
  --threads THREADS    Número de threads para execução paralela (padrão: 5)
  --timeout TIMEOUT    Timeout para requisições em segundos (padrão: 5)
  --quick              Executar apenas testes rápidos com parâmetros comuns
  --output OUTPUT      Arquivo para salvar os resultados
```

### Exemplos

#### Modo rápido (apenas testes com parâmetros comuns)

```bash
python waf-bypass-tester.py https://example.com/login.jsp --quick
```

#### Aumentar número de threads e timeout

```bash
python waf-bypass-tester.py https://example.com/login.jsp --threads 10 --timeout 10
```

#### Salvar resultados em arquivo

```bash
python waf-bypass-tester.py https://example.com/login.jsp --output resultados.txt
```

## Como funciona

A ferramenta opera em várias etapas:

1. **Análise baseline**: Obtém uma resposta normal do endpoint para comparação
2. **Teste rápido**: Verifica parâmetros comuns com payloads eficazes
3. **Teste completo**: Se solicitado, realiza testes abrangentes em todos os parâmetros
4. **Análise de resultado**: Detecta respostas que indicam bypass bem-sucedido

## Parâmetros e Payloads

A ferramenta inclui uma extensa lista de:

- Parâmetros comuns em aplicações web organizados por categorias (autenticação, admin, debug, etc.)
- Payloads para diversos tipos de ataques (SQLi, XSS, SSTI, LFI, RFI, etc.)
- Técnicas de evasão de WAF (encoding, ofuscação, caracteres especiais, etc.)

## Detecção de bloqueios

A ferramenta usa várias técnicas para identificar bloqueios de WAF:

- Detecção de código de status HTTP 403
- Identificação de mensagens de bloqueio ("Sorry, you have been blocked")
- Análise de similaridade para detectar respostas sutilmente diferentes

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests.

## Disclaimer

Esta ferramenta deve ser usada apenas para testes autorizados de segurança. Seu uso em sistemas sem permissão é ilegal e antiético. Os autores não se responsabilizam pelo uso indevido desta ferramenta.

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para detalhes.
