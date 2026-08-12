# Aula 03 — Protocolos de Rede e NAT
**Prof. Gabriel Azenha Fachim** | Unidade 1 — Segurança de redes locais e de longa distância

> Pergunta-guia da aula: **Como a internet ignora um endereço privado?**

---

## 0. Retomando (Aula 02)
- Modelo TCP/IP → 4 camadas: Aplicação, Transporte, Internet, Acesso à Rede
- Endereçamento IP e sub-redes → IPv4, máscara, CIDR
- Portas e serviços → TCP x UDP, portas conhecidas (22, 53, 80/443, 445, 3389)
- NAT (introdução) → tradução de endereços privados p/ IP público
- Ataques de rede / caso Mirai Botnet → sniffing, spoofing, MITM, DoS/DDoS, credenciais padrão expostas
- Fases de teste de invasão → reconhecimento → varredura → enumeração → exploração → pós-exploração → relatório

---

## 1. DHCP — como um host recebe endereço
> Antes de traduzir (NAT), o host já precisou **receber** um IP. Sigla: **DORA**

| Etapa | Ação |
|---|---|
| **D**iscover | host novo manda broadcast: "há DHCP na rede?" |
| **O**ffer | servidor oferece IP + máscara + gateway + DNS |
| **R**equest | host solicita formalmente o IP ofertado (pode haver +1 servidor) |
| **A**cknowledge | servidor confirma a concessão (**lease**) — host passa a usar o IP por um período |

⚠️ Esse endereço concedido é, quase sempre, de faixa **privada** → é ele que o NAT vai traduzir na saída.

---

## 2. Protocolos de rede — revisão rápida

| Protocolo | Porta | Transporte | Função |
|---|---|---|---|
| HTTP/HTTPS | 80/443 | TCP | navegação web (S = criptografado) |
| DNS | 53 | TCP/UDP | traduz nomes ↔ IPs |
| SSH | 22 | TCP | acesso remoto administrativo, criptografado |
| FTP | 20/21 | TCP | transferência de arquivos (sem cripto, historicamente) |
| SMTP/POP3/IMAP | 25/110/143 | TCP | envio/recebimento de e-mail |
| DHCP | 67/68 | UDP | atribuição automática de IP (foco de hoje) |

---

## 3. Endereçamento: válido x inválido

- **Endereço válido (público)** → roteável na internet, único no mundo, atribuído por entidade regional (ex: **LACNIC** na América Latina)
- **Endereço inválido (privado)** → não roteável, reservado pela **RFC 1918**, uso interno. Roteadores da internet **descartam** pacotes com esses endereços de origem/destino

### Faixas reservadas

| Faixa | CIDR | Uso |
|---|---|---|
| 10.0.0.0 – 10.255.255.255 | /8 | privada — redes grandes/corporativas |
| 172.16.0.0 – 172.31.255.255 | /12 | privada — provedores/data centers |
| 192.168.0.0 – 192.168.255.255 | /16 | privada — a mais usada em casa |
| 127.0.0.0 – 127.255.255.255 | /8 | loopback (127.0.0.1 = próprio host) |
| 169.254.0.0 – 169.254.255.255 | /16 | link-local/APIPA — atribuído quando DHCP falha |

### Por que a internet "ignora" um endereço privado
- **Não é boa educação, é regra padrão dos roteadores** (RFC 1918): pacote saindo de 192.168.1.10 direto p/ internet → descartado no 1º roteador do provedor
- **Consequência prática:** host privado sozinho não fala com a internet — falta endereço "real" no cabeçalho
- **Solução:** dispositivo de borda (roteador/gateway) reescreve o endereço de origem antes de sair → **isso é o NAT**

### Cenário típico doméstico
1 IP público (contrato) + dezenas de dispositivos (DHCP dá IP privado a cada um) → **1 portão de saída** = NAT.

---

## 4. NAT — Network Address Translation
> Dispositivo de rede (tipicamente roteador) reescreve em tempo real IP (e frequentemente porta) dos pacotes que o atravessam, permitindo que hosts privados usem a internet via 1 endereço válido.

- **Onde vive:** na borda da rede (roteador doméstico, firewall corporativo, gateway de nuvem)

### Funcionamento passo a passo (exemplo)

| Momento | IP origem | Porta origem | IP destino |
|---|---|---|---|
| Antes do NAT (rede local) | 192.168.1.10 | 51422 | 200.150.10.5 |
| Depois do NAT (internet) | 203.0.113.7 | 40001 | 200.150.10.5 |
| Resposta chega no roteador | 200.150.10.5 | 80 | 203.0.113.7:40001 |
| Depois do NAT (volta p/ rede local) | 200.150.10.5 | 80 | 192.168.1.10:51422 |

📌 O roteador guarda essa correspondência numa **tabela de tradução** — é assim que sabe devolver a resposta pro host certo.

---

## 5. Tipos de NAT

### 5.1 Static NAT (1:1 fixo)
- Cada IP privado ↔ 1 IP público específico, **permanentemente**
- Uso: servidores internos que precisam ser sempre acessados pelo mesmo endereço (web, e-mail)
- Custo: 1 IP público por dispositivo — pouco escalável

```bash
# 192.168.1.50 -> 200.1.1.20
iptables -t nat -A PREROUTING -d 200.1.1.20 -j DNAT --to-destination 192.168.1.50
iptables -t nat -A POSTROUTING -s 192.168.1.50 -j SNAT --to-source 200.1.1.20
```

### 5.2 Dynamic NAT (1:1 via pool)
- Roteador tem **pool** de IPs públicos, empresta temporariamente a quem precisa sair
- Uso: empresas com vários IPs públicos, mas menos que hosts ativos simultâneos
- Limite: pool esgotado → próximo dispositivo fica sem internet

```bash
# 192.168.1.10-.14 -> 200.1.1.10-.12
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth1 -j SNAT --to-source 200.1.1.10-200.1.1.12
```

### 5.3 PAT / NAT Overload (o mais usado — o "NAT do dia a dia")
- **Muitos:1** — centenas de dispositivos compartilham 1 IP público, diferenciados pela **porta TCP/UDP de origem**
- Padrão em roteadores domésticos e na maioria das redes corporativas
- Vantagem: milhares de hosts navegando com 1 único IPv4 público

```bash
# 192.168.1.10, .11, .12 -> 200.1.1.10 (diferenciados pela porta)
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o eth0 -j MASQUERADE
```

### Tabela de tradução PAT (exemplo com conflito de porta)

| IP interno | Porta interna | IP público | Porta traduzida | Destino |
|---|---|---|---|---|
| 192.168.1.10 | 51422 | 203.0.113.7 | 40001 | 200.150.10.5:80 |
| 192.168.1.11 | 50110 | 203.0.113.7 | 40002 | 142.250.0.14:443 |
| 192.168.1.12 | 51422 | 203.0.113.7 | 40003 | 13.107.42.14:443 |
| 192.168.1.15 | 50110 | 203.0.113.7 | 40004 | 200.150.10.5:80 |

→ 2 máquinas usaram a **mesma porta interna** (51422 e 50110) — roteador resolve atribuindo **portas públicas distintas**.

---

## 6. Exemplo resolvido — rastreando 1 tradução NAT
Cenário: `192.168.0.20` acessa site na porta 443, roteador c/ IP público `187.45.10.30`

1. **Pacote sai do host** → origem `192.168.0.20:53210` → destino `8.8.4.4:443`
2. **Roteador aplica NAT** → reescreve origem p/ `187.45.10.30:61010`, registra na tabela
3. **Resposta chega ao roteador** → servidor responde pro único endereço que conhece: `187.45.10.30:61010`
4. **Roteador desfaz o NAT** → consulta tabela, identifica `192.168.0.20:53210`, reencaminha pra dentro

---

## 7. NAT saída x entrada

| | Outbound (saída) | Inbound (entrada) |
|---|---|---|
| Automático? | Sim — transparente | **Não existe por padrão** |
| Como funciona | host interno inicia conexão → roteador cria tradução automaticamente | alguém de fora tenta iniciar → roteador não sabe pra qual máquina mandar → **descarta** |

---

## 8. Controles de NAT — expondo serviço de propósito

### Port Forwarding
- Regra explícita, **porta por porta**: "tudo que chegar na porta pública X → host interno Y, porta Z"
- Ex: servidor Minecraft em `192.168.1.50`, porta pública `25565` → redirecionada pro IP interno; resto do PC continua fechado
- ✅ Seguro (expõe só o serviço desejado) | ❌ trabalhoso se exigir muitas portas

### DMZ (Zona Desmilitarizada)
- Aponta **1 IP privado** e tira ele **inteiramente** da proteção do firewall — recebe TODO tráfego de entrada não tratado por outra regra
- Ex: PS5/Xbox com NAT Estrito → coloca IP do console na DMZ → "NAT Aberto" instantâneo
- ✅ Resolve bloqueios de NAT rapidamente | ❌ **altíssimo risco** se usado em PC — sem barreira nenhuma do roteador

---

## 9. Consequências do NAT — o que não funciona bem

| Caso | Problema |
|---|---|
| **P2P** (torrent, blockchain) | cada par precisa aceitar conexões de outros — sem regra de entrada, difícil se enxergarem |
| **VoIP/videochamadas** | protocolos como **SIP** carregam IP interno **dentro dos dados**, não só no cabeçalho — NAT comum não sabe reescrever |
| **Jogos online** | sessão P2P com jogador-host exige que outros conectem direto nele — geralmente precisa port forwarding |

### NAT Traversal — como contornar

| Técnica | Sigla | O que faz |
|---|---|---|
| **STUN** | Session Traversal Utilities for NAT | descobre qual IP público/porta o NAT está usando p/ o host |
| **TURN** | Traversal Using Relays around NAT | quando conexão direta é impossível, servidor **retransmite** todo o tráfego |
| **ICE** | Interactive Connectivity Establishment | testa várias possibilidades (direta/STUN/TURN) e escolhe a que funciona — usado por **WebRTC** |

**Fluxo típico (chamada WebRTC):**
1. STUN descobre o IP → 2. TURN atua como relé se firewall bloquear → 3. ICE escolhe o melhor caminho → 4. conexão estabelecida (peers trocam candidatos)

---

## 10. NAT e segurança — cuidado com a ilusão

| O que o NAT **resolve** | O que ele **NÃO resolve** |
|---|---|
| Oculta topologia interna — invasor externo só enxerga o IP público do roteador, dificultando reconhecimento direto | **Não filtra, não inspeciona, não autentica** — não decide o que é tráfego malicioso, não substitui firewall com inspeção de pacotes |

> Efeito colateral útil ≠ controle de segurança desenhado pra isso.

---

## 11. NAT em escala — CGNAT (Carrier-Grade NAT)
- Com esgotamento do IPv4, **provedores** também aplicam NAT: cliente recebe IP privado do próprio provedor, traduzido junto com centenas de outros clientes → **1 único IP público** na saída da operadora
- **Impacto usuário:** serviços que exigem porta de entrada exclusiva (jogos, câmeras, servidores) ficam quase impossíveis de configurar sem cooperação do provedor
- **Impacto investigações:** vários clientes compartilham o mesmo IP público visível externamente → identificar o responsável exige **log de portas do provedor**

### Caso real — rastreabilidade
- Mesmo IP público em log de acesso pode ser **centenas de clientes diferentes** (CGNAT)
- Pra identificar o responsável: cruzar **IP público + porta de origem + horário exato** com os logs de tradução do provedor — sem isso, rastreabilidade se perde

---

## 12. Panorama — IPv6 acaba com o NAT?
- **Por que NAT existiu:** IPv4 tem ~4,3 bilhões de endereços — insuficiente hoje
- **Com IPv6:** cada dispositivo pode ter IP público próprio e único → tecnicamente NAT deixa de ser necessário p/ escassez
- **Mas:** segurança continua dependendo do **firewall** — sem NAT, o "ocultamento por acidente" desaparece, exposição direta exige firewall bem configurado

---

## 13. Conectando com testes de invasão

| Fase | O que NAT muda |
|---|---|
| **Do lado de fora** | teste black box só enxerga IP(s) público(s) — hosts internos ficam ocultos atrás do NAT |
| **Serviços expostos de propósito** | o que é alcançável de fora costuma ter port forwarding/DMZ configurado → **alvo inicial mais relevante** |
| **Movimento lateral** | uma vez dentro, testador já está "atrás" do NAT — enxerga a rede local como qualquer outro dispositivo |

---

## 14. Ferramentas de reconhecimento

### traceroute / tracert
- Envia pacotes com **TTL crescente**, registra qual roteador responde em cada salto → reconstrói caminho até o destino
- **Ligação com NAT:** saltos com endereços privados (10.x, 172.16-31.x, 192.168.x) revelam existência de NAT na rota
- ⚠️ Limitação: firewalls podem bloquear ICMP e mascarar saltos intermediários

### nslookup / dig
- Consultam DNS: nome ↔ IP, registros **MX** (e-mail), **NS** (servidores de nome)
- Reconhecimento: subdomínios expostos (vpn.exemplo.com, mail.exemplo.com) revelam serviços públicos da organização

### whois
- Revela: quem registrou o domínio, datas de criação/expiração, servidores de nome, dono de bloco de IPs públicos (via RDAP/whois de IP)
- ⚠️ Muitos registros usam **WHOIS privacy** — oculta dados pessoais do titular

---

## 15. Vulnerabilidades — padrões comuns em protocolos

| Padrão | Exemplo |
|---|---|
| **Confiança implícita** | ARP e DHCP assumem que qualquer resposta na rede local é legítima → abre espaço p/ **spoofing** |
| **Ausência de criptografia** | protocolos legados (Telnet, FTP, HTTP) trafegam dados/credenciais em texto claro → vulneráveis a **sniffing** |
| **Configuração exposta** | serviços administrativos (RDP, SSH, painéis) expostos direto à internet, sem NAT/firewall → amplia superfície de ataque |

> Toda vulnerabilidade de rede é, no fundo, um desvio do que o protocolo previa.

---

## 16. Exercícios de fixação (individual) — respondidos

**1) Por que um endereço 192.168.0.5 nunca aparece diretamente na internet?**
Não aparece, pois é um endereço que está numa faixa de endereço reservada para IPs privados. No caso dessa: 192.168.0.0 – 192.168.255.255, é a mais usada em redes domésticas.

**2) Diferencie Static NAT, Dynamic NAT e PAT (NAT Overload) em uma frase cada.**
- **Static NAT** → usa um IP privado para um IP público (1:1 fixo)
- **Dynamic NAT** → roteador tem uma "piscina" de IPs públicos, empresta pra quem precisa, é um agiota
- **PAT (NAT Overload)** → centenas de dispositivos compartilham o mesmo IP público, diferencia-se pela porta TCP/UDP de origem

**3) Um roteador tem apenas um IP público. Como ele consegue atender 30 dispositivos ao mesmo tempo?**
NAT (Tradução de Endereço de Rede) usa as portas de rede para dividir um único IP público entre 30 aparelhos. Ele troca o IP interno de cada dispositivo pelo IP público e adiciona um número de porta único para saber para onde enviar cada resposta da internet.

**4) Por que aplicativos de videochamada costumam usar STUN/TURN/ICE?**
Para atravessar barreiras de rede (como roteadores com NAT e firewalls) que impedem dois dispositivos de se conectarem diretamente na internet. Eles garantem que o áudio e o vídeo cheguem ao destino com o menor atraso possível.

**5) O que é CGNAT e por que ele dificulta expor um serviço próprio à internet?**
NAT aplicado pelo próprio provedor, compartilhando IP público entre vários clientes. Ele dificulta expor um serviço pois o seu roteador recebe um IP privado pela operadora, não um IP público real.
- Você não consegue abrir portas (port forwarding) no roteador da operadora para direcionar tráfego externo ao seu servidor.
- **Bloqueio de entrada:** o sistema do provedor descarta conexões que chegam da internet sem uma solicitação prévia feita por você.

---

## 17. Atividade em sala (duplas) — tabelas de tradução NAT, respondida

### Cenário A — Tradução simples
Host `192.168.1.5:52000` acessa site na porta 443 via IP público `201.10.5.90`.

| IP interno | Porta interna | IP público | Porta traduzida | Destino |
|---|---|---|---|---|
| 192.168.1.5 | 52000 | 201.10.5.90 | 40500 (porta pública qualquer, escolhida pelo roteador) | site:443 |

### Cenário B — Conflito de portas
Dois hosts internos diferentes tentam sair usando a mesma porta de origem (50000). Como o roteador resolve esse conflito no PAT:

No PAT (NAT Overload), todos compartilham o mesmo IP público — quem diferencia as conexões é a porta. Então, quando o roteador percebe que a porta 50000 já está em uso por outra tradução ativa, ele **não reaproveita** essa porta para o segundo host: atribui uma porta pública diferente (ex: 50000 → 40010 para o host A, e 50000 → 40011 para o host B).

### Cenário C — Expondo um serviço
A empresa quer que um servidor web interno (`192.168.1.20:8080`) seja acessível pela porta 80 do IP público. Configuração necessária: **Port Forwarding**.

- Regra no roteador: *"tudo que chegar na porta pública 80, vindo da internet, deve ser encaminhado para 192.168.1.20, na porta 8080"*
- Isso cria uma tradução fixa e direcionada para entrada (inbound) — diferente do NAT de saída, que é automático. Sem essa regra explícita, o roteador descartaria qualquer tentativa de conexão externa, já que não saberia para qual host interno mandar o tráfego.
- Vantagem sobre a DMZ: apenas a porta 80 fica exposta — o resto do servidor (SSH, outras portas) continua protegido pelo firewall do roteador.

---

## 18. Glossário rápido

| Termo | Definição |
|---|---|
| Endereço válido | IP público, único, roteável na internet |
| Endereço inválido | IP privado (RFC 1918), não roteável |
| NAT | tradução de endereços — privados navegam via IP público |
| PAT / NAT Overload | vários hosts privados compartilhando 1 IP público, diferenciados por porta |
| Port Forwarding | regra que encaminha porta pública específica p/ host interno |
| CGNAT | NAT aplicado pelo próprio provedor, compartilhando IP público entre vários clientes |
| STUN/TURN/ICE | técnicas de NAT Traversal usadas por VoIP/videochamadas |

---

## 19. Próxima aula (4ª semana)
- Continuidade: **varredura e enumeração**
- Aprofundar varredura de portas e enumeração de serviços na prática
- Relacionar protocolos + NAT com interpretação de resultados de varredura
- Introduzir ferramentas de varredura usadas em testes de invasão autorizados
- **Tarefa:** revisar cenários de NAT de hoje + trazer 1 dúvida/curiosidade sobre endereçamento ou tradução de endereços

**Bibliografia:** TANENBAUM, A. S. *Redes de computadores*, 4.ed. Rio de Janeiro: Campus, 2003. | HUNT, C.; RÜDIGER, D. *Linux: servidores de rede*. Rio de Janeiro: Ciência Moderna, 2004.
