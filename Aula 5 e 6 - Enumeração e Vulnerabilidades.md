# Aula 06 — Da enumeração à vulnerabilidade

> **Segurança Digital • 6º semestre** — Prof. Gabriel Azenha Fachim
> Subunidade 2.2: Interpretando dados e planejando a investigação

**Pergunta central:** qual achado merece investigação primeiro, e com qual evidência?

**Ideia-chave:** a versão **sugere hipóteses**. Ela **não confirma** vulnerabilidade, impacto nem possibilidade de exploração.

---

## 0. Ponto de partida (Aula 05)

| Arquivo | Conteúdo |
|---|---|
| `resultado.txt` | Portas, estados, serviços e versões detectadas pelo Nmap |
| `banner.txt` | Informações que o próprio serviço revelou na conexão |

**Competência:** analisar ferramentas para exploração, identificando possibilidades de ataque.

**Objetivos:** interpretar evidências de enumeração → pesquisar em fontes confiáveis → avaliar aplicabilidade e prioridade → planejar testes em ambiente autorizado.

---

## 1. Leitura da enumeração

### Dado → Contexto → Hipótese → Decisão

```
Dado            Contexto        Hipótese          Decisão
80/tcp open  →  Apache 2.4.x →  CVE aplicável? →  Validar ou descartar
```

> A ferramenta coleta sinais. O analista constrói o significado.

### O que cada coluna do Nmap responde

```
22/tcp   open   ssh   OpenSSH 8.9p1
```

| Campo | Pergunta que responde |
|---|---|
| `22/tcp` | Qual porta e protocolo de transporte? |
| `open` | Como o alvo respondeu ao scan? |
| `ssh` | Qual serviço o Nmap **inferiu**? |
| `OpenSSH 8.9p1` | Qual produto e build **parecem** ativos? |

### Estados de porta (aberta ≠ vulnerável)

| Estado | Significado |
|---|---|
| `open` | Há uma aplicação aceitando conexões |
| `closed` | O host respondeu, mas não há serviço escutando |
| `filtered` | Algum controle impediu a conclusão do scan |
| `open\|filtered` | A resposta não permitiu distinguir os dois estados |

> O estado de porta descreve **conectividade**. Vulnerabilidade exige uma **condição explorável**.

### Produto, versão e build

- Exemplos: OpenSSH 8.9p1, Apache 2.4.57, nginx 1.24.0
- ⚠️ **Backport:** pacotes recebem correções **sem mudar a versão**. É uma das principais causas de falso positivo em análise por versão.

### Fontes de identificação

| Fonte | O que usa |
|---|---|
| `nmap -sV` | Sondas e assinaturas pré-definidas |
| Banner direto | Resposta textual do serviço ou headers HTTP |
| Comportamento | Recursos e respostas estruturais observadas |

> Quanto mais fontes **independentes** concordarem, maior a confiança.

### Confiança da evidência

| Nível | Critério |
|---|---|
| **Baixa** | Inferência genérica ("servidor web em 80/tcp") |
| **Média** | Nmap identifica produto e família de versão |
| **Alta** | Banner, resposta HTTP e comportamento confirmam a **mesma build** |

> Registre como chegou à conclusão. A confiança faz parte do achado.

---

## 2. Conceitos

### Exposição × Fraqueza × Vulnerabilidade

| Termo | Definição |
|---|---|
| **Exposição** | Serviço acessível a partir de determinada origem |
| **Fraqueza** | Configuração ou implementação que reduz a segurança esperada |
| **Vulnerabilidade** | Condição técnica que pode causar impacto quando explorada |

> A mesma exposição pode ser necessária ao negócio e ainda exigir controles.

### CVE × CWE × Exploit

| Termo | O que é |
|---|---|
| **CVE** | Identificador de um registro público de vulnerabilidade |
| **CWE** | Categoria de fraqueza (ex.: validação inadequada de entrada) |
| **Exploit** | Código ou procedimento que demonstra ou aproveita uma condição |

- Um CVE pode **não ter** exploit público.
- Um exploit pode exigir condições **ausentes** no alvo.

### Anatomia de um CVE

```
CVE - 2024 - 12345
 │     │      └── sequência única naquele ano
 │     └───────── ano da atribuição do registro
 └─────────────── programa de identificação
```

### CPE: liga o produto ao registro

```
cpe:2.3:a:vendor:produto:versao:*:*:*:*:*:*:*
        │   │       │       └── faixa que precisa ser conferida
        │   └───────┴────────── fabricante e nome normalizado
        └────────────────────── tipo: a = application
```

> CPE ajuda na correlação, mas nomes e faixas ainda precisam de validação.

---

## 3. CVSS

### Gravidade ≠ Prioridade

| | Mede |
|---|---|
| **CVSS** | Características técnicas de gravidade, com vetor padronizado |
| **Prioridade** | Gravidade + exposição + criticidade do ativo + controles + exploração observada |

> Um score alto em um sistema isolado pode ficar atrás de uma falha explorada em produção.

### Versões

| | Grupos de métricas | Observação |
|---|---|---|
| **CVSS 3.1** | Base, Temporal, Environmental | Métricas comuns: AV, AC, PR, UI, S, C, I, A |
| **CVSS 4.0** | Base, Threat, Environmental, Supplemental | Separa melhor o impacto no sistema vulnerável e nos subsequentes |

> Ao registrar um score, informe **a versão do CVSS e o vetor completo**.

### CVSS 3.1: métricas

| Métrica | Nome | Pergunta |
|---|---|---|
| `AV` | Attack Vector | De onde o ataque parte? (N/A/L/P) |
| `AC` | Attack Complexity | Qual a complexidade? |
| `PR` | Privileges Required | Quais privilégios são exigidos? |
| `UI` | User Interaction | Precisa de interação do usuário? |
| `S` | Scope | O impacto atravessa a fronteira de segurança? |
| `C` | Confidentiality | Impacto em confidencialidade |
| `I` | Integrity | Impacto em integridade |
| `A` | Availability | Impacto em disponibilidade |

- AV, AC, PR e UI são as **métricas de explorabilidade**: quais condições o atacante precisa reunir antes de causar impacto.
- S, C, I e A são **escopo e impacto**. O vetor descreve a vulnerabilidade; o contexto do ativo define a urgência real.

### Exemplo de vetor

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| AV:N | AC:L | PR:N | UI:N | S:U | C/I/A:H |
|---|---|---|---|---|---|
| Rede | Baixa complexidade | Nenhum privilégio | Sem interação | Escopo inalterado | Impacto alto |

### CVSS 4.0: o que mudou

| Grupo | Função |
|---|---|
| **Threat** | Incorpora maturidade de exploração ao cálculo contextual |
| **Environmental** | Adapta o resultado ao ambiente avaliado |
| **Supplemental** | Registra informações úteis **sem alterar o score base** (Automatable, Recovery, Safety) |

---

## 4. Fontes de pesquisa

| Fonte | Para quê |
|---|---|
| **CVE.org** | Registro e referências do programa CVE |
| **NVD** | Enriquecimento: CPE, CVSS e referências |
| **Advisory** | Fabricante: versões afetadas e correção |
| **Exploit-DB** | PoCs e pesquisa local via SearchSploit |

> Priorize **fontes primárias** para confirmar produto, faixa afetada e correção.

### Fluxo na NVD

1. Pesquise o nome exato do produto e a versão observada.
2. Abra o registro e confira a descrição, o CPE e o intervalo de versões.
3. Leia as referências do fabricante e as notas de atualização.
4. Registre o CVSS **com versão e vetor**, não apenas o número.

### Advisory do fabricante

| Confirma | Explica |
|---|---|
| Produtos afetados, versões corrigidas, pré-condições, mitigação oficial | Backports, diferenças entre builds, configuração necessária, impacto real no ecossistema |

> Quando NVD e advisory discordam, entenda o pacote antes de concluir.

### SearchSploit

```bash
searchsploit openssh
searchsploit "Apache 2.4"
searchsploit --cve 2021-41773
```

> A existência de um PoC **aumenta a relevância** da hipótese, mas **não prova aplicabilidade**.
> **Antes de executar:** leia o código, confirme alvo e versão, revise dependências e use **somente em laboratório**.

### Checklist de PoC (nunca execute código desconhecido em produção)

| # | Pergunta |
|---|---|
| 01 | O código corresponde ao mesmo produto? |
| 02 | A versão e a arquitetura coincidem? |
| 03 | A configuração necessária existe? |
| 04 ⚠️ | O teste pode causar indisponibilidade? |

---

## 5. Correlação e validação

### Cadeia de análise

```
Porta → Serviço → Versão → CVE → CVSS → Aplicável?
```

> Em qualquer etapa, evidência insuficiente **devolve a investigação ao passo anterior**.

### Por que a versão pode enganar

- O fornecedor aplicou **backport** do patch.
- O banner foi **ocultado, alterado** ou está desatualizado.
- A funcionalidade vulnerável está **desabilitada** no alvo.
- O exploit exige **módulo, SO ou arquitetura** diferentes.

> Conclusão correta: **"potencialmente afetado, pendente de validação"**.

### Validação: da hipótese à confirmação

| Passo | Ação | Detalhe |
|---|---|---|
| 1 | **Reproduzir** | Confirme a evidência inicial |
| 2 | **Contextualizar** | Mapeie build, configuração e exposição |
| 3 | **Testar** | Escolha um teste seguro e autorizado |
| 4 | **Documentar** | Registre resultado e limitações |

> Uma boa validação também explica **por que uma hipótese foi descartada**.

### O que investigar primeiro

| Fator | Pergunta |
|---|---|
| Exploração | Há abuso conhecido no mundo? |
| Exposição | O serviço está acessível? |
| Impacto | O ativo e os dados são críticos? |
| Viabilidade | Existem pré-condições? |

### Modelo simples de prioridade

| Prioridade | Critério |
|---|---|
| 🔴 **Urgente** | Exposto, aplicável, com alto impacto ou exploração observada |
| 🟠 **Alta** | Condições presentes e ativo importante |
| 🟡 **Média** | Hipótese plausível, com controles ou impacto limitado |
| ⚪ **Baixa** | Pouca evidência, sem exposição ou não aplicável |

---

## 6. Contexto do ativo

### Superfície de ataque observável

| Origem | O que aparece |
|---|---|
| **Externa** | Serviços alcançáveis pela internet, DNS, certificados, APIs e painéis |
| **Interna** | Serviços corporativos, administração, bancos de dados e protocolos legados |
| **Local** | Software instalado, permissões, credenciais e configurações do host |

> A origem do teste muda o que está exposto e quais controles entram no caminho.

### Perguntas antes de buscar CVE

- [ ] Qual é o produto exato, a versão, a build e a distribuição?
- [ ] O serviço está exposto para qual rede e quais usuários?
- [ ] Há autenticação, proxy, WAF, segmentação ou outro controle?
- [ ] A funcionalidade vulnerável está ativa e acessível?
- [ ] Qual impacto o comprometimento teria para o negócio?

### Coleta complementar

```bash
# HTTP: além do banner
curl -I http://<alvo>
curl -vk https://<alvo>/
nmap -p80,443 --script http-title,http-headers <alvo>

# TLS: certificado e cifras
openssl s_client -connect <alvo>:443 -servername <nome>
nmap -p443 --script ssl-cert,ssl-enum-ciphers <alvo>

# Nmap: intensidade da detecção de versão
nmap -sV --version-light <alvo>
nmap -sV --version-intensity 7 <alvo>
nmap -sV --version-trace <alvo>   # mostra POR QUE o Nmap chegou à identificação
```

| Coleta | Observar |
|---|---|
| HTTP | Redirecionamentos, headers, cookies, título, TLS, virtual hosts, tecnologias aparentes |
| TLS | CN/SAN, emissor, validade, protocolos e cifras suportadas |

- Headers podem **omitir ou falsificar** o produto. Confirme com outras evidências.
- O certificado pode revelar **nomes internos** que merecem enumeração autorizada.
- Maior intensidade no `-sV` envia mais sondas e aumenta tempo, ruído e risco operacional.

---

## 7. Priorização: métricas complementares

| Métrica | Pergunta | Resumo |
|---|---|---|
| **CVSS** | Quão grave pode ser sob condições definidas? | Gravidade |
| **EPSS** | Qual a probabilidade estimada de exploração nos próximos 30 dias? | Probabilidade futura |
| **CISA KEV** | Há evidência de exploração conhecida no mundo real? | Exploração atual |

> Combine os sinais com exposição e criticidade. **Nenhum decide sozinho.**

### EPSS

| Campo | Significado |
|---|---|
| **Score** | Probabilidade (0 a 1) de exploração observada nos 30 dias seguintes |
| **Percentil** | Posição relativa do CVE em relação aos demais registros |

> O valor muda **diariamente**. Registre a data da consulta e não trate como certeza.

### CISA KEV

- Reúne vulnerabilidades com evidência de **exploração ativa**.
- Estar no KEV **aumenta a urgência** da análise e da remediação.
- Não estar no KEV **não demonstra** que o CVE é seguro.
- Mesmo assim, confirme se o produto e a versão do ambiente estão realmente afetados.

### O risco em quatro dimensões

| Dimensão | Pergunta |
|---|---|
| **Aplicabilidade** | A condição existe no alvo? |
| **Exposição** | Quem consegue alcançá-la? |
| **Ameaça** | Há exploit, EPSS alto ou KEV? |
| **Impacto** | O que o atacante afetaria? |

> A prioridade cresce quando as quatro dimensões **apontam na mesma direção**.

---

## 8. Estudo de caso: Apache HTTP Server 2.4.49

> Versão histórica, usada só em laboratório. **Não teste serviços públicos.**

```
80/tcp open http Apache httpd 2.4.49
GET / HTTP/1.1
Server: Apache/2.4.49
```

**Hipótese:** investigar o CVE-2021-41773 e as condições para path traversal.

| O que confirmar | |
|---|---|
| Versão | Afeta **especificamente** a 2.4.49 |
| Configuração | A exploração depende de configuração específica de arquivos e aliases |
| Impacto | Leitura de arquivos fora do diretório esperado |
| Histórico | A 2.4.50 corrigiu **de forma incompleta** e recebeu outro CVE |

### Evidência necessária

| Versão | Configuração | Impacto |
|---|---|---|
| A coleta confirma **exatamente** 2.4.49? | O alias e o acesso ao caminho vulnerável estão presentes? | A resposta comprova leitura indevida **sem alterar o sistema**? |

> Um teste seguro coleta **somente a evidência mínima** para confirmar ou descartar.

### Conclusões possíveis

| Resultado | Quando |
|---|---|
| 🟢 **Confirmado** | Versão, configuração e comportamento correspondem à falha |
| 🔴 **Não aplicável** | Produto presente, mas a versão ou a condição necessária não existe |
| 🟡 **Inconclusivo** | Evidência insuficiente ou teste seguro não pôde ser executado |

> "Inconclusivo" é melhor do que afirmar algo sem evidência.

---

## 9. Registro de achado técnico

| Campo | Conteúdo |
|---|---|
| **Título** | Produto, condição e impacto principal |
| **Evidência** | Comando, saída, data, origem e alvo |
| **Aplicabilidade** | Versão, build, configuração e exposição |
| **Risco** | CVSS, EPSS, KEV, ativo e controles |
| **Correção** | Versão corrigida, mitigação e responsável |
| **Reteste** | Critério objetivo para encerramento |

---

## Prática guiada

**Preparação:** crie uma pasta para guardar comandos, saídas e referências.

| Alvo autorizado | Regra estrita |
|---|---|
| VM de laboratório, Metasploitable ou serviço fornecido pelo professor | Pesquisa e validação **apenas no escopo definido**. Nada de testar sistemas públicos |

| Etapa | O que fazer | Entrega / pergunta |
|---|---|---|
| **1. Ler e filtrar** | `cat resultado.txt` · `grep "open" resultado.txt` · `nmap -sV -oN versoes.txt` | Liste porta, serviço, versão e confiança. Se faltar versão, planeje uma coleta adicional **antes** de pesquisar CVE |
| **2. Construir hipótese** | Ex.: Apache HTTP Server · 2.4.x · Nmap + header HTTP · **falta:** build exata e distribuição | Qual informação mudaria sua decisão de investigar ou descartar? |
| **3. Pesquisar e registrar** | Produto/versão exata → CVE + descrição → faixa afetada → CVSS, EPSS, KEV → exploit/PoC público → próximo passo | — |
| **4. Testar aplicabilidade** | Comparar versão × faixa afetada → conferir SO, arquitetura, módulo e configuração → verificação não destrutiva → registrar resultado, limitações e evidência | Pare se o teste sair do escopo ou puder comprometer a disponibilidade |

---

## Atividade em duplas: três serviços, uma decisão

```
22/tcp   open  ssh    OpenSSH 7.6p1
80/tcp   open  http   Apache httpd 2.4.x
3306/tcp open  mysql  MySQL 5.7.x
```

**Desafio:** escolher qual achado investigar primeiro e defender a escolha logicamente. Não presuma vulnerabilidade apenas pela versão.

**Tempo:** 30 min de análise + 5 min de apresentação por grupo.

| Critério | Pergunta |
|---|---|
| **Evidência** | A versão e a exposição foram bem justificadas? |
| **Pesquisa** | As fontes confirmam a faixa afetada descrita? |
| **Análise** | Falsos positivos e pré-condições foram considerados? |
| **Decisão** | A prioridade e o próximo passo fazem sentido? |

### Matriz de análise (minha entrega)

| Porta | Serviço | Versão | CVE | CVSS | Exploit? | Evidência | Próximo Passo |
|---|---|---|---|---|---|---|---|
| 22 | ssh | OpenSSH 7.6 | CVE-2025-32728 | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N | Não | Versão 7.6p1 via Nmap -sV. Está na faixa afetada (7.4 a 9.9) | Confirmar a build e disto pelo banner |
| 80 | http | Apache httpd 2.4.x | **Indeterminado**, porque a versão está incompleta. Hipóteses válidas só se for 2.4.49 (CVE-2021-41773) ou 2.4.49/2.4.50 (CVE-2021-42013) | N/A até confirmar a versão | N/A | Nmap -sV. Confiança **baixa/média**: só a família da versão é conhecida | Utilizar comando mais completo para determinar a versão completa. |
| 3306 | mysql | MySql 5.7.x | CVE-2017-3302 | N/A | Sim. permite que um servidor MySQL malicioso force o encerramento abrupto (crash) de aplicações clientes conectadas através de uma falha de uso de memória após liberação na biblioteca libmysqlclient.so | Nmap -sV. Confiança **média**. | Dependendo da versão, podem haver outros tipos de vulnerabilidades ou resoluções para essa, verificar mais a fundo com comandos mais precisos. |

---

## Fixação: perguntas e respostas

| Pergunta | Resposta |
|---|---|
| Por que uma porta aberta não confirma vulnerabilidade? | Confirma apenas um serviço acessível, não uma condição explorável |
| Diferença entre CVE, CWE e exploit? | CVE identifica o registro, CWE classifica a fraqueza, exploit demonstra a falha |
| Como CVSS, EPSS e KEV se complementam? | CVSS = gravidade · EPSS = probabilidade futura · KEV = exploração atual |
| Duas causas de falso positivo por versão? | Backport de patches, banner impreciso ou funcionalidade vulnerável inativa |
| Fatores além do CVSS que alteram a prioridade? | Exposição de rede, criticidade do ativo, controles e viabilidade para o atacante |

---
