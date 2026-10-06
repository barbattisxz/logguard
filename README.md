# 🛡️ LogGuard

Mini-WAF em **Python puro (zero dependências)** que analisa logs Apache/Nginx em
*Combined Log Format* e detecta ataques **linha a linha** e **por padrão de comportamento de IP**.

> Ferramenta defensiva: apenas **lê** logs. Nunca envia requisições.

## O que detecta

| Categoria | Exemplos | Regras |
|---|---|---|
| **SQL Injection** | `UNION SELECT`, `OR 1=1`, `OR '1'='1'`, `;--`, `SLEEP()`, `INFORMATION_SCHEMA` | SQLI-001..006 |
| **XSS** | `<script>`, `onerror=`, `alert(`, `document.cookie` | XSS-001..005 |
| **Path Traversal** | `../`, `%2e%2e%2f`, `%252e` (double encoding), `/etc/passwd` | TRAV-001..002 |
| **Command Injection** | `; cat`, `\| ls`, `` `id` ``, `$(whoami)` | CMDI-001..003 |
| **Scanners** | sqlmap, Nikto, Nmap, DirBuster, Burp, gobuster… (User-Agent) | SCAN-001 |
| **Caminhos sensíveis** | `/.env`, `/.git/`, `/phpmyadmin`, `/wp-login.php`, `/backup.sql` | PATH-001..003 |
| **Brute force** | muitos 401/403 do mesmo IP (limiar configurável) | BEHAV-001 |
| **Varredura de diretórios** | pico de 404 do mesmo IP (limiar configurável) | BEHAV-002 |

Extras: normalização anti-evasão (URL-decode repetido, `+`, `/**/`, `\xHH` do Apache),
alerta quando o ataque recebeu resposta **HTTP 2xx** (pode ter funcionado), saída JSON e
código de saída para CI.

## Requisitos

Python 3.8+ — nada para instalar.

## Uso rápido

```bash
# 1. gerar um log de demonstração (tráfego legítimo + ataques simulados)
python samples/generate_sample_log.py

# 2. analisar
python -m logguard samples/access_demo.log
```

### Opções

```
python -m logguard ACCESS_LOG [opções]

  --brute-threshold N     401/403 por IP para brute force   (padrão 10)
  --scan-threshold N      404 por IP para varredura         (padrão 20)
  --min-severity LEVEL    low | medium | high | critical
  --json                  saída em JSON
  --summary-only          só o resumo
  --limit N               máximo de achados detalhados (0 = todos)
  --top N                 tamanho do ranking de IPs
  --no-color              sem cores ANSI
```

`ACCESS_LOG` pode ser `-` para ler da entrada padrão:
`tail -n 5000 /var/log/nginx/access.log | python -m logguard -`

### Códigos de saída

| Código | Significado |
|---|---|
| 0 | nenhum achado |
| 1 | achados encontrados (ótimo para falhar um pipeline de CI) |
| 2 | erro de uso (arquivo inexistente, parâmetro inválido) |

## Testes

```bash
python -m unittest discover -v
```

## Arquitetura

```
logguard/
  parser.py    Combined Log Format -> LogEntry
  rules.py     assinaturas (regex) + normalização anti-evasão
  detector.py  Analyzer: regras por linha + contadores por IP
  report.py    relatório em texto/JSON
  cli.py       argparse + códigos de saída
```

## Adicionando uma regra

Em `logguard/rules.py`, acrescente uma linha em `RULES`:

```python
_r("SQLI-007", CAT_SQLI, "high", "Stacked query", "request", r";\s*drop\s+table"),
```

## Limitações (honestidade técnica)

- Detecção por **assinaturas** → pode gerar falsos positivos (ex.: um site WordPress legítimo
  recebe acessos a `/wp-login.php`) e não pega ataques inéditos ou payloads no corpo de POST
  (o log de acesso não registra o corpo).
- Os limiares de brute force/varredura contam o **total por IP no arquivo**, não uma janela de tempo.
- Não é substituto de um WAF em tempo real (ModSecurity, Cloudflare…); é uma ferramenta de
  análise *post-mortem* e de triagem.

## Licença

MIT
