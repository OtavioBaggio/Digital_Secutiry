# Aula 04 — Varredura de Portas e Enumeração
**Prof. Gabriel Azenha Fachim** | Unidade 1 — Segurança de redes locais e de longa distância | Subunidade 1.2

> Pergunta-guia da aula: **Se um host está atrás do NAT, como um testador de fora descobre o que existe ali?**

---

## 0. Retomando (Aula 03)
- Endereços válidos/inválidos → IP público (roteável) x IP privado (RFC 1918)
- NAT: Static, Dynamic, PAT/Overload → como o roteador reescreve endereços e portas
- Tabela de tradução do NAT → IP interno+porta ↔ IP público+porta traduzida
- Port Forwarding, DMZ, NAT Traversal (STUN/TURN/ICE)
- CGNAT e IPv6
- Ferramentas de reconhecimento → traceroute, nslookup/dig, whois

## Agenda de hoje
1. Da tradução de endereços à varredura de portas
2. Revisão: handshake TCP + fases do teste de invasão
3. Varredura de portas: conceito, estados, tipos de scan
4. Nmap: ferramenta padrão de mercado
5. Enumeração de serviços: banner grabbing e NSE
6. NAT e varredura: o que um testador externo enxerga
7. Aspectos legais
8. Atividade prática guiada + em duplas

---

## 1. Fases do teste de invasão — onde a varredura entra

| # | Fase | O que faz |
|---|---|---|
| 1 | **Reconhecimento** | coleta pública — whois, DNS, redes sociais (Aula 03) |
| 2 | **Varredura** | descobrir portas abertas e serviços ativos no alvo — **foco de hoje** |
| 3 | **Enumeração** | extrair detalhes de cada serviço — versões, banners, usuários — **foco de hoje** |
| 4 | **Exploração** | usar falhas identificadas p/ obter acesso (próximas semanas) |

---

## 2. Revisão: handshake TCP (three-way handshake)
> Processo do TCP p/ criar conexão confiável entre 2 aparelhos antes de enviar dados reais. 3 passos: **SYN, SYN-ACK, ACK**.

| Etapa | O que acontece |
|---|---|
| **SYN** (Sincronizar) | cliente envia pacote com flag SYN → pede início da conversa, avisa seu nº de sequência inicial |
| **SYN-ACK** (Sincronizar+Confirmar) | servidor confirma o pedido (ACK) e envia seu próprio nº de sequência (SYN) |
| **ACK** (Confirmar) | cliente confirma o nº do servidor → conexão pronta, dados podem trafegar |

```
Cliente                    Servidor
   |---------- SYN --------->|
   |<------- SYN-ACK --------|
   |---------- ACK --------->|
   |   conexão estabelecida  |
```

📌 O **SYN scan** interrompe esse processo de propósito logo após o SYN-ACK.

---

## 3. Varredura de portas — conceito

> **Port scanning:** técnica de enviar pacotes especialmente formados a um conjunto de portas de um host, e interpretar as respostas (ou ausência delas) para descobrir quais serviços estão escutando ali.

- **Por que é o próximo passo:** reconhecimento passivo (whois, DNS) revela domínios/IPs — a varredura revela o que está **ativo** neles
- **Autorizado x não autorizado:** a mesma técnica usada em pentest contratado é usada por atacante — o que muda é a **autorização**

### Os três estados possíveis de uma porta

| Estado | O que acontece | Significado |
|---|---|---|
| **Aberta** | scanner manda SYN → recebe SYN-ACK | serviço responde normalmente |
| **Fechada** | scanner manda SYN → recebe RST | host ativo, mas porta sem serviço |
| **Filtrada** | scanner manda SYN → **sem resposta** | firewall descarta o pacote silenciosamente |

---

## 4. Tipos de scan TCP
> Cada tipo interrompe o handshake em um ponto diferente — muda velocidade e discrição.

| Tipo | Também chamado | Como funciona | Característica |
|---|---|---|---|
| **SYN scan** | Half-open / stealth | envia SYN, recebe SYN-ACK, **nunca completa com ACK** | rápido e o mais usado — exige privilégio administrativo |
| **Connect scan** | TCP connect | completa o handshake normalmente, como app real | mais lento e detectável, **não exige** privilégio especial |
| **ACK scan** | — | envia apenas ACK, sem handshake prévio | não detecta porta aberta — **mapeia regras de firewall** |
| **FIN / NULL / XMAS** | scans stealth | envia flags incomuns (FIN, nenhuma, ou várias) fora de contexto | tenta passar despercebido por firewalls simples |

📌 **FIN** = sinal de controle p/ fechar conexão de forma limpa — avisa que o remetente terminou de enviar dados e quer encerrar a sessão. Usado "fora de contexto" (sem handshake prévio) pra confundir firewalls simples.

### Controlando a velocidade — timing templates (`-T`)

```
-T0        -T1         -T2        -T3       -T4         -T5
Paranoico  Sorrateiro  Educado    Normal    Agressivo   Insano
◄────── mais lento / mais discreto ─── mais rápido / mais detectável ──►
```

📌 Na prática: **-T4 é o padrão recomendado**. Extremos (-T0/-T1) servem p/ evasão deliberada; -T5 arrisca perder respostas.

### Por que a varredura UDP é mais difícil

| TCP (com handshake) | UDP (sem handshake) |
|---|---|
| ausência de resposta ao SYN geralmente = porta filtrada — comportamento previsível e rápido | ausência de resposta pode ser porta **aberta OU filtrada** — só confirma enviando payload específico do protocolo |

→ Por isso **scans UDP são muito mais lentos**.

---

## 5. NAT e varredura — o que muda na prática
> A tabela de tradução da Aula 03 explica por que um scan externo enxerga tão pouco.

- Um scan de fora pra dentro (**black box**) atinge só o **endereço público do roteador**
- As portas "abertas" que aparecem são exatamente as com **port forwarding** ou **DMZ** configurados
- Os demais hosts internos permanecem **completamente invisíveis**

| De fora (antes do NAT) | De dentro (depois de acesso inicial) |
|---|---|
| scan só vê IP público + portas explicitamente encaminhadas (normalmente 2-3 serviços, no máximo) | testador enxerga a rede local como qualquer outro dispositivo dela — **sem NAT no caminho** |

### Diagrama — o que o testador realmente enxerga
```
Testador externo → Internet → Roteador/NAT (203.0.113.7)
                                    │
                    ┌───────────────┼───────────────┬───────────────┐
              192.168.1.10    192.168.1.11    192.168.1.12    192.168.1.13
              sem forwarding  porta 443→web   sem forwarding  sem forwarding
                (invisível)      (VISÍVEL)      (invisível)     (invisível)
```
→ **Só a porta com port forwarding aparece** — os demais hosts ficam fora do alcance do scan.

---

## 6. Nmap — a ferramenta padrão de mercado
> **Network Mapper** — código aberto, criado em 1997 — ferramenta de varredura mais usada em pentests, CTFs e certificações.

- **O que faz:** varre portas TCP/UDP, identifica versões de serviço, detecta SO, roda scripts de enumeração — tudo em 1 ferramenta
- **Onde roda:** linha de comando (Linux/Windows/macOS) + interface gráfica **Zenmap** p/ iniciantes
- **Por que aprender primeiro:** é o denominador comum — dominá-lo facilita aprender qualquer outra ferramenta depois

### Sintaxe e flags mais usadas
`nmap [flags] [alvo]`

| Flag | Significado |
|---|---|
| `-sS` | SYN scan (half-open) — tipo padrão e mais usado |
| `-sT` | Connect scan — completa handshake, não exige privilégio |
| `-sU` | varredura de portas UDP |
| `-sV` | detecta versão do serviço em cada porta aberta |
| `-O` | tenta identificar o sistema operacional do alvo |
| `-p` | define quais portas varrer (ex: `-p 1-1000` ou `-p 80,443`) |
| `-A` | modo agressivo — combina `-sV`, `-O` e scripts básicos |
| `-T4` | define velocidade do scan (0=muito lento, 5=muito rápido) |

### Combinando flags para cada situação

```bash
nmap -sS -p- alvo
# varre todas as 65.535 portas TCP com SYN scan — completo, porém lento

nmap -sV -sC alvo
# detecta versões + roda scripts padrão do NSE — bom p/ 1º relatório

nmap -Pn -p 80,443 alvo
# ignora checagem de host ativo — útil quando alvo bloqueia ping mas portas respondem

nmap -sU -sS -p U:53,T:22,80 alvo
# combina varredura UDP e TCP na mesma execução, portas por protocolo

nmap -oN saida.txt alvo
# salva saída em arquivo de texto — essencial p/ documentar teste de invasão
```

### Escolhendo o scan certo (fluxo)
```
Tem privilégio administrativo?
  ├── Não → -sT (Connect scan)
  └── Sim → Precisa ser discreto?
              ├── Sim → -sS (SYN scan)
              └── Não → -sS -A -T4 (scan agressivo)

  Suspeita de serviço UDP? → adicionar -sU
```

### Exemplo de leitura de saída real
```
$ nmap -sV -p 1-1000 192.168.1.20

PORT     STATE    SERVICE   VERSION
22/tcp   open     ssh       OpenSSH 8.9p1
80/tcp   open     http      Apache httpd 2.4.52
443/tcp  open     https     Apache httpd 2.4.52
3306/tcp closed   mysql
8080/tcp filtered http-proxy
```
📌 Porta 3306 (MySQL) fechada, 8080 filtrada — provável firewall bloqueando silenciosamente.

### OS fingerprinting (flag `-O`)
Compara características da pilha TCP/IP do alvo com base de assinaturas conhecidas.

| Pista | Windows (típico) | Linux (típico) |
|---|---|---|
| TTL inicial | 128 | 64 |
| Tamanho janela TCP | 65.535 ou 8.192 | 5.840 ou 29.200 |
| Ordem opções TCP | MSS, NOP, WS, NOP, NOP, SACK | MSS, SACK, TS, NOP, WS |
| Resposta a pacotes malformados | varia por versão | segue RFC de forma mais estrita |

📌 TTL é a pista mais rápida: TTL 64 chegando como 61 sugere ~3 saltos de roteador até o alvo.

---

## 7. Enumeração de serviços

### Varredura x Enumeração
> **Varredura é ampla e rasa; enumeração é estreita e profunda.**

```
VARREDURA → descobre portas abertas: 21 22 25 53 80 110 143 443 3306 8080
                     │
                     ▼ (foca em 1 porta)
ENUMERAÇÃO → porta 22 → OpenSSH 8.9p1, Ubuntu → usuários, algoritmos, banners...
```

### Banner grabbing
> Técnica mais simples de enumeração: perguntar diretamente ao serviço quem ele é. Muitos serviços se apresentam automaticamente ao aceitar conexão (o "banner").

```bash
$ nc 192.168.1.20 22
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4

$ nc 192.168.1.20 21
220 ProFTPD 1.3.5a Server ready.
```

**Boas práticas de defesa (hardening de banners):**
- Remover versões dos banners (`Server: nginx` em vez de `Server: nginx/1.26.2`)
- Remover headers desnecessários (`X-Powered-By`, `X-AspNet-Version`)
- Desabilitar banners detalhados em SSH/FTP/SMTP quando possível
- **Não** criar banners falsos como defesa principal (é *security through obscurity* — scanners fazem fingerprinting por outros meios)
- Manter serviços atualizados (ocultar versão reduz reconhecimento, mas **não corrige vulnerabilidades**)
- Fechar portas/serviços desnecessários com firewall/security groups
- Restringir serviços administrativos por VPN, allowlist de IP ou rede interna
- Usar reverse proxy/WAF para evitar exposição direta de apps e servidores backend

### O que cada protocolo costuma revelar

| Serviço | Porta | O que a enumeração revela |
|---|---|---|
| SMB | 445 | nome do domínio, compartilhamentos, versão do Windows, usuários locais |
| FTP | 21 | login anônimo aceito?, versão do servidor, listagem de diretórios |
| SSH | 22 | versão do OpenSSH, algoritmos de criptografia aceitos |
| HTTP/HTTPS | 80/443 | tecnologia do servidor web, CMS, diretórios expostos, certificado TLS |
| SNMP | 161 | configuração de rede, uptime, às vezes credenciais (community strings padrão) |
| DNS | 53 | transferência de zona mal configurada pode revelar todos os hosts do domínio |

### Nmap Scripting Engine (NSE)
> Nmap não para na varredura — roda scripts prontos de enumeração e detecção de vulnerabilidades.

```bash
nmap --script vuln -p 80,443 192.168.1.20
# bateria de scripts de detecção de vulnerabilidades conhecidas
```

| Categoria | O que faz |
|---|---|
| `--script default` | scripts seguros e rápidos, rodados com `-sV -A` |
| `--script safe` | não afetam o alvo — apenas coletam informação |
| `--script vuln` | procuram vulnerabilidades conhecidas especificamente |

### Além do Nmap — panorama de ferramentas especializadas

| Ferramenta | Função |
|---|---|
| `enum4linux` | enumeração completa de compartilhamentos/usuários SMB/Windows |
| `smbclient` | navega/acessa compartilhamentos SMB diretamente, como cliente |
| `nikto` | varredura de vulnerabilidades específicas em servidores web |
| `gobuster` / `dirb` | descobre diretórios e arquivos escondidos em servidor web |

### Nmap x Masscan x Zenmap

| Ferramenta | Ponto forte | Limitação |
|---|---|---|
| **Nmap** | detecção de versão, NSE, fingerprinting — mais completo | mais lento em varreduras muito grandes (milhões de IPs) |
| **Masscan** | varre a internet inteira em minutos — extremamente rápido | não detecta versão/serviço por padrão, menos preciso |
| **Zenmap** | interface gráfica do Nmap — bom p/ iniciantes/relatórios visuais | mesmas limitações de velocidade + camada extra de UI |

📌 Na prática: **Masscan** para descobrir hosts ativos em escala, **Nmap** para aprofundar em cada um.

---

## 8. Técnicas de evasão (avançado)

### Fragmentação de pacotes (`-f`)
Divide o pacote TCP em fragmentos menores, dificultando inspeção por firewalls simples (que inspecionam pacote a pacote).
```
Pacote completo --(-f)--> [frag 1][frag 2][frag 3][frag 4]
```

### Decoy scan (`-D`)
Mistura IPs falsos com o real — dificulta saber qual origem é o testador de fato.
```
203.0.113.9  ─┐
203.0.113.7  ─┼──► Alvo   (1 real + 2 decoys via -D)
203.0.113.4  ─┘
```

📌 Outras técnicas: scan lento (-T0/-T1) p/ ficar abaixo do limiar de detecção; spoofing de origem (`-S`), mais útil em laboratório que em campo.

---

## 9. Aspectos legais — varredura não autorizada é crime
> **Lei 12.737/2012** (já vista na Aula 02) tipifica invasão de dispositivo alheio — varrer portas sem autorização já pode ser enquadrado como preparação ou tentativa, dependendo do contexto/intenção.

- **Escopo por escrito:** todo pentest profissional começa com contrato definindo exatamente quais IPs e horários estão autorizados
- **Ambientes de prática:** `scanme.nmap.org` e plataformas como TryHackMe/HackTheBox — praticar de forma legal
- **Regra de ouro:** nunca varra um alvo sem permissão explícita — nem "só para aprender"

---

## 10. Caso real — bancos de dados expostos sem autenticação
> Padrão recorrente desde 2017: instâncias sem senha, encontradas por varredura em massa.

```
MongoDB / Elasticsearch / Redis  →  0.0.0.0:porta padrão  →  Internet pública  →  Scanner automatizado
                                                                    (encontra em minutos)
```

📌 Lição: o mesmo comando `-sV` que rodamos identifica esse tipo de exposição — **a defesa começa por varrer a própria rede.**

---

## 11. Atividade prática guiada — primeiro scan
Alvo público de prática: **scanme.nmap.org** (mantido pelo próprio projeto Nmap para prática autorizada)

1. Confirmar o alvo
2. Rodar `nmap -sV -T4 scanme.nmap.org`
3. Ler a saída — quais portas, quais serviços, quais estados
4. Registrar as portas abertas encontradas

## 12. Atividade em sala (duplas) — interpretando resultados

- **Cenário A:** resultado com 3 portas abertas (22, 80, 3306) → identificar serviços prováveis + 1 risco de cada
- **Cenário B:** porta aparece "filtered" em vez de "closed" → diferença prática entre os dois estados
- **Cenário C:** alvo atrás de NAT com só a porta 443 exposta → o que isso implica sobre os outros hosts da rede?

### Correção — pontos-chave
1. Porta 3306 (MySQL) exposta é quase sempre risco — bancos de dados não deveriam estar acessíveis diretamente da internet
2. "Filtered" = existe firewall no caminho | "Closed" = host respondeu, mas não há serviço ali
3. Só a porta 443 exposta atrás de NAT sugere port forwarding único — os demais hosts provavelmente seguem inacessíveis de fora

---

## 13. Glossário rápido

| Termo | Definição |
|---|---|
| Port scanning | técnica de descobrir portas abertas em um host |
| SYN scan | scan que interrompe o handshake TCP após o SYN-ACK |
| Porta filtrada | firewall descarta o pacote antes de qualquer resposta |
| Enumeração | extração de detalhes de um serviço já identificado como aberto |
| Banner grabbing | ler a mensagem de apresentação automática de um serviço |
| NSE | Nmap Scripting Engine — scripts prontos de enumeração/detecção |

---

## 14. Exercícios de fixação — respondidos

**1) Diferencie varredura de portas e enumeração de serviços em uma frase cada.**
- **Varredura de portas** é a técnica de testar um conjunto de portas de um host para descobrir quais estão abertas, fechadas ou filtradas — é ampla e rasa, olha todo o alvo de uma vez.
- **Enumeração de serviços** é o processo de extrair detalhes profundos de um serviço já identificado como aberto (versão, banners, usuários, configurações) — é estreita e profunda, foca em 1 porta/serviço por vez.

**2) Por que um SYN scan é considerado mais "discreto" que um Connect scan?**
Porque o SYN scan (half-open) envia o SYN, recebe o SYN-ACK, mas **nunca completa o handshake com o ACK final** — a conexão TCP nunca é totalmente estabelecida. Como muitas aplicações e logs só registram conexões completas, esse scan tende a deixar menos rastro. Já o Connect scan completa o handshake normalmente, como uma aplicação real faria, o que faz a conexão aparecer inteira nos logs do sistema-alvo — sendo mais lento e mais fácil de detectar.

**3) O que significa uma porta aparecer como "filtered" em vez de "closed"?**
- **Closed (fechada):** o host está ativo e respondeu ao scan (geralmente com um pacote RST), mas não há nenhum serviço escutando naquela porta.
- **Filtered (filtrada):** o scanner não recebeu resposta alguma — isso indica que existe um **firewall** no caminho descartando o pacote silenciosamente, sem confirmar nem negar a existência de um serviço ali. É uma barreira ativa de segurança, diferente da simples ausência de serviço.

**4) Explique como o NAT limita o que uma varredura externa consegue enxergar.**
Como hosts com IP privado não são endereçáveis diretamente da internet, um scan externo (black box) só consegue atingir o **endereço IP público do roteador**. As únicas portas que aparecem "abertas" nesse scan são exatamente aquelas que têm uma regra explícita de **port forwarding** (ou uma DMZ) configurada, direcionando o tráfego para um host interno específico. Todos os demais dispositivos da rede local — que não têm nenhuma porta redirecionada — permanecem completamente invisíveis para quem está testando de fora, pois o roteador não sabe para qual máquina interna encaminhar aquele tráfego e simplesmente descarta a tentativa.

**5) Cite duas informações que o banner grabbing pode revelar sobre um serviço.**
- O **software** que está rodando o serviço (ex: OpenSSH, ProFTPD, Apache) e a **versão exata** dele (ex: OpenSSH 8.9p1, ProFTPD 1.3.5a) — informação valiosa para buscar vulnerabilidades conhecidas (CVEs) daquela versão específica.
- Também pode revelar o **sistema operacional** por trás do serviço (ex: "Ubuntu-3ubuntu0.4" no banner do SSH) e, em alguns casos, até detalhes extras como nome do host ou mensagens de boas-vindas do sistema, que ajudam a mapear o ambiente do alvo.

