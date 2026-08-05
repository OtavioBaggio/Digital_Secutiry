# Aula 2 – Fundamentos de Segurança da Informação e Redes

**Aluno:** José Otávio R. Baggio

---

# Tríade CIA

A Tríade CIA representa os três pilares fundamentais da Segurança da Informação. Toda informação deve preservar essas três propriedades.

## Confidencialidade
Garantir que apenas pessoas ou sistemas autorizados tenham acesso aos dados.

## Integridade
Garantir que os dados permaneçam corretos, íntegros e sem alterações indevidas, preservando seu estado original.

## Disponibilidade
Garantir que os dados e serviços estejam acessíveis quando forem necessários.

---

# Modelo Zero Trust

O modelo **Zero Trust** segue o princípio:

> **"Nunca confiar, sempre verificar."**

Cada solicitação de acesso deve ser autenticada e autorizada, independentemente de sua origem (usuário, dispositivo ou rede).

Princípios principais:

- Não existe confiança automática.
- Todo acesso deve ser validado.
- Usuários e aplicações recebem apenas as permissões estritamente necessárias (**Princípio do Menor Privilégio**).

---

# Reconhecimento e Enumeração

## Reconhecimento (Reconnaissance)

É a fase de coleta de informações sobre um alvo.

### Por que manter softwares atualizados?

Se um invasor identificar a versão do sistema operacional, framework ou aplicação utilizada, ele poderá pesquisar vulnerabilidades conhecidas daquela versão, facilitando um ataque.

## Enumeração

Após o reconhecimento, a enumeração aprofunda as informações obtidas, identificando, por exemplo:

- Portas abertas
- Serviços em execução
- Usuários
- Compartilhamentos
- Recursos disponíveis

---

# Senhas

As senhas são utilizadas para restringir o acesso a sistemas e informações.

## Boas práticas

- O **comprimento da senha é mais importante que a complexidade**.
- Frases longas são mais fortes e mais fáceis de memorizar.

Exemplo:

```
o-dia-está-nublado
```

é geralmente mais segura que:

```
G@br13l!
```

Além disso:

- Nunca reutilizar a mesma senha em diferentes serviços.
- Utilizar senhas únicas para cada conta.

## Autenticação Multifator (MFA)

Mesmo que uma senha seja comprometida, o invasor ainda precisará de um segundo fator de autenticação, como:

- Aplicativo autenticador
- Token
- Biometria
- Chave de segurança

## Gerenciadores de Senhas

Permitem criar e armazenar senhas longas, fortes e únicas para cada serviço, sem depender da memória do usuário.

---

# Como uma senha é comprometida?

Na maioria das vezes, uma senha **não é descoberta por força bruta**, mas por meios mais simples.

Principais formas:

## Vazamento de dados

A senha (ou seu hash) é exposta após um incidente de segurança em algum serviço.

## Reaproveitamento de senhas (Credential Stuffing)

Uma senha vazada em um site é automaticamente testada em diversos outros serviços.

## Phishing

O usuário é enganado para informar voluntariamente sua senha em um site ou mensagem falsa.

---

# Introdução aos Testes de Invasão

Os testes de invasão (Pentests) avaliam a segurança de sistemas e redes, podendo ser realizados tanto em redes locais quanto através da internet.

## LAN (Local Area Network)

- Rede local
- Poucos hosts
- Mesmo domínio físico ou lógico

## WAN (Wide Area Network)

- Rede de grande escala
- Interliga diversas LANs
- Exemplo: Internet

## Internetworking

Interligação de diferentes redes para permitir comunicação entre elas.

---

# Modelo OSI x Modelo TCP/IP

O **Modelo OSI** é um modelo teórico com **7 camadas**.

O **Modelo TCP/IP** é o modelo utilizado na Internet, composto por **4 camadas**.

## Modelo OSI

1. Aplicação
2. Apresentação
3. Sessão
4. Transporte
5. Rede
6. Enlace
7. Física

## Modelo TCP/IP

### Aplicação

Protocolos utilizados diretamente pelos usuários e aplicações.

Exemplos:

- HTTP
- HTTPS
- DNS
- SSH
- FTP

### Transporte

Responsável pela comunicação entre processos.

Protocolos:

- TCP
- UDP

### Internet

Responsável pelo endereçamento e roteamento.

Protocolos:

- IP
- ICMP

### Acesso à Rede

Responsável pela comunicação física e lógica com a rede.

Exemplos:

- Ethernet
- Wi-Fi
- ARP
- Endereço MAC

Cada camada possui protocolos específicos responsáveis por suas funções.

---

# TCP x UDP

## TCP (Transmission Control Protocol)

- Orientado à conexão.
- Garante entrega.
- Mantém a ordem dos pacotes.
- Possui confirmação de recebimento.

Usado em:

- HTTP/HTTPS
- SSH
- FTP

## UDP (User Datagram Protocol)

- Não orientado à conexão.
- Não garante entrega.
- Menor latência.
- Mais rápido.

Usado em:

- Streaming
- Jogos online
- VoIP
- DNS

---

# ARP

**ARP (Address Resolution Protocol)** converte um endereço IP em um endereço MAC dentro da rede local.

É um protocolo frequentemente explorado em ataques como:

- ARP Spoofing
- Man-in-the-Middle (MITM)

---

# Segurança em Redes Wi-Fi

## WPA2

Padrão consolidado de criptografia para redes sem fio.

## WPA3

Evolução do WPA2, corrigindo diversas vulnerabilidades e aumentando significativamente a segurança.

> **Observação:** nas anotações aparece "WPA/WPS2", mas o correto é **WPA2**. O **WPS (Wi-Fi Protected Setup)** é outra tecnologia, utilizada para facilitar a conexão de dispositivos, e não um protocolo de criptografia.

---

# Classes de Endereços IP

## Classe A

- Primeiro octeto: **1 a 126**
- Máscara padrão:

```
255.0.0.0
```

(0 é reservado e 127 é utilizado para loopback.)

## Classe B

Primeiro octeto:

```
128 a 191
```

Máscara:

```
255.255.0.0
```

## Classe C

Primeiro octeto:

```
192 a 223
```

Máscara:

```
255.255.255.0
```

## Classe D

Primeiro octeto:

```
224 a 239
```

Reservada para multicast.

## Classe E

Primeiro octeto:

```
240 a 255
```

Reservada para pesquisas e testes.

---

# Endereçamento IPv4 e CIDR

Exemplo:

```
192.168.1.10/24
```

Onde:

- **192.168.1** → identifica a rede
- **10** → identifica o host
- **/24** → máscara de sub-rede

Equivalência:

```
/24 = 255.255.255.0
```

---

# Firewall e ACL

## Firewall

Analisa todo o tráfego de rede e aplica regras para permitir ou bloquear comunicações.

Os critérios normalmente utilizados são:

- IP de origem
- IP de destino
- Porta
- Protocolo

## ACL (Access Control List)

Lista de regras que define quais usuários, dispositivos ou pacotes podem acessar determinados recursos.

Pode controlar:

- Acesso à rede
- Pastas
- Arquivos
- Equipamentos
- Rotas

---

# VLANs

Uma **VLAN (Virtual Local Area Network)** permite dividir logicamente uma rede física em várias redes menores.

Vantagens:

- Maior segurança
- Melhor organização
- Redução do domínio de broadcast
- Isolamento entre setores

---

# Redes Wi-Fi

## Rede Aberta

Não utiliza criptografia.

Todo o tráfego pode ser capturado por qualquer pessoa próxima.

## WPA2

Padrão amplamente utilizado com criptografia.

## WPA3

Versão mais segura, protegendo melhor contra ataques de força bruta e outras vulnerabilidades.

---

# Ataques Comuns em Redes

## Sniffing

Captura do tráfego de rede.

## Spoofing

Falsificação de identidade (IP, MAC, DNS etc.).

## Man-in-the-Middle (MITM)

O atacante intercepta a comunicação entre duas partes.

## DoS / DDoS

Ataques de negação de serviço.

Objetivo:

- Tornar um serviço indisponível.

---

# Tipos de Teste de Invasão

## Black Box

O testador não recebe nenhuma informação prévia.

Simula um atacante externo.

## Grey Box

O testador recebe informações parciais.

## White Box

O testador recebe todas as informações do ambiente.

---

# Exercícios de Fixação

## 1)

Classifique cada item na camada correta do TCP/IP.

| Item | Camada |
|------|---------|
| HTTP | Aplicação |
| ARP | Acesso à Rede |
| UDP | Transporte |
| Ethernet | Acesso à Rede |

---

## 2)

Qual a máscara equivalente a **/27**?

```
255.255.255.224
```

Cálculo:

```
32 - 27 = 5

2⁵ = 32 endereços

32 - 2 = 30 hosts utilizáveis
```

---

## 3)

Um pacote chega na porta **443** de um servidor.

Resposta:

- Transporte: **TCP**
- Serviço: **HTTPS** (HTTP Seguro)

---

## 4)

Diferença entre TCP e UDP.

- TCP oferece conexão, confiabilidade e entrega ordenada.
- UDP prioriza velocidade e baixa latência, sem garantia de entrega.

---

## 5)

Por que um IP privado (ex.: 192.168.0.5) nunca aparece diretamente na Internet?

Porque o roteador realiza a tradução de endereços através do **NAT (Network Address Translation)**, convertendo IPs privados em um IP público. Isso economiza endereços IPv4 públicos e fornece uma camada adicional de isolamento, embora **não substitua um firewall**.

---

# Cenários

## Cenário A

A empresa possui a rede:

```
192.168.10.0/24
```

### Hosts utilizáveis

```
32 - 24 = 8

2⁸ = 256 endereços

256 - 2 = 254 hosts utilizáveis
```

### Broadcast

```
192.168.10.255
```

---

## Cenário B

Dividir:

```
192.168.20.0/24
```

em **4 sub-redes iguais**.

### Nova máscara

```
/26

255.255.255.192
```

Cada bloco possui:

```
256 - 192 = 64 endereços
```

Sub-redes:

```
192.168.20.0/26
192.168.20.64/26
192.168.20.128/26
192.168.20.192/26
```

---

## Cenário C

Hosts:

```
10.0.5.12/26
10.0.5.80/26
```

### Cálculo

```
32 - 26 = 6

2⁶ = 64 endereços por sub-rede
```

Sub-redes:

```
10.0.5.0   - 10.0.5.63
10.0.5.64  - 10.0.5.127
```

Resultado:

- **10.0.5.12** pertence à primeira sub-rede.
- **10.0.5.80** pertence à segunda sub-rede.

**Conclusão:** não estão na mesma sub-rede.
