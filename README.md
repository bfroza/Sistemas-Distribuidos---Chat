# Explicação Técnica Detalhada - Chat P2P com Blockchain

## Índice
1. [Visão Geral](#visão-geral)
2. [Arquitetura do Sistema](#arquitetura-do-sistema)
3. [Funcionamento da Blockchain](#funcionamento-da-blockchain)
4. [Comunicação P2P](#comunicação-p2p)
5. [Mecanismos de Segurança](#mecanismos-de-segurança)
6. [Peer Malicioso](#peer-malicioso)
7. [Fluxos de Dados](#fluxos-de-dados)

---

## Visão Geral

Este projeto implementa um **sistema de chat peer-to-peer (P2P) descentralizado** que utiliza **tecnologia blockchain** para garantir a integridade e autenticidade das mensagens trocadas entre os participantes. Cada mensagem enviada torna-se um bloco validado criptograficamente e encadeado aos blocos anteriores, criando um registro imutável e distribuído do histórico de conversas.

### Objetivos do Projeto

1. **Demonstrar conceitos de blockchain** de forma prática e acessível
2. **Implementar comunicação P2P** sem necessidade de servidor central
3. **Validação criptográfica distribuída** usando SHA-256
4. **Ilustrar segurança da informação** através da tentativa de adulteração
5. **Ensinar sobre imutabilidade** e integridade de dados distribuídos

### Tecnologias Utilizadas

- **Python 3.7+**: Linguagem de programação principal
- **Tkinter**: Interface gráfica de usuário
- **Socket (TCP)**: Comunicação entre peers
- **Multicast (UDP)**: Descoberta automática de peers na rede
- **Hashlib (SHA-256)**: Cálculo de hashes criptográficos
- **Threading**: Execução concorrente de tarefas
- **JSON**: Serialização de dados para transmissão

---

## Arquitetura do Sistema

### 1. blockchain.py - Núcleo da Blockchain

Este módulo implementa a estrutura fundamental da blockchain e suas operações.

#### Classe Block

Representa um bloco individual na cadeia. Cada bloco contém:

```python
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index              # Posição sequencial na cadeia (0, 1, 2, ...)
        self.timestamp = timestamp      # Momento de criação (Unix timestamp)
        self.data = data                # Conteúdo da mensagem
        self.previous_hash = previous_hash  # Hash do bloco anterior
        self.hash = self.calculate_hash()  # Hash deste bloco
```

**Método calculate_hash():**
```python
def calculate_hash(self):
    """Calcula o hash SHA-256 do bloco."""
    block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
    return hashlib.sha256(block_string.encode()).hexdigest()
```

Este método concatena todos os dados do bloco e aplica a função SHA-256, gerando um hash de 64 caracteres hexadecimais. Qualquer alteração mínima nos dados resulta em um hash completamente diferente.

**Método from_dict():**
```python
@staticmethod
def from_dict(block_dict):
    """Cria um bloco a partir de um dicionário e VALIDA o hash."""
    block = Block(
        block_dict["index"],
        block_dict["timestamp"],
        block_dict["data"],
        block_dict["previous_hash"]
    )
    # VALIDAÇÃO CRÍTICA: verifica se o hash recebido bate com o calculado
    if block.hash != block_dict["hash"]:
        raise ValueError(f"Hash inválido!")
    return block
```

Esta validação é **crucial** para a segurança. Antes da correção, o código simplesmente sobrescrevia o hash calculado com o hash recebido, permitindo blocos fraudulentos. Agora, se o hash não bate, uma exceção é lançada.

#### Classe Blockchain

Gerencia a cadeia completa de blocos.

**Inicialização:**
```python
def __init__(self):
    self.chain = [self.create_genesis_block()]
```

A blockchain sempre começa com o **bloco genesis**, que é o primeiro bloco e serve como âncora para toda a cadeia.

**Bloco Genesis:**
```python
def create_genesis_block(self):
    """Cria o bloco genesis com timestamp FIXO."""
    return Block(0, 1700000000.0, "Genesis Block", "0")
```

O timestamp fixo garante que todos os peers criem o mesmo bloco genesis, permitindo sincronização. Se cada peer criasse um genesis com `time.time()`, teriam hashes diferentes e não conseguiriam se comunicar.

**Adicionar Bloco:**
```python
def add_block(self, data):
    """Cria e adiciona um novo bloco à cadeia."""
    previous_block = self.get_latest_block()
    new_block = Block(
        len(self.chain),
        time.time(),
        data,
        previous_block.hash
    )
    self.chain.append(new_block)
    return new_block
```

Cada novo bloco referencia o hash do bloco anterior através do campo `previous_hash`, criando o **encadeamento**.

**Validação da Cadeia:**
```python
def is_valid(self):
    """Verifica se toda a blockchain está íntegra."""
    for i in range(1, len(self.chain)):
        current = self.chain[i]
        previous = self.chain[i - 1]

        # Validação 1: Hash correto?
        if current.hash != current.calculate_hash():
            return False

        # Validação 2: Encadeamento correto?
        if current.previous_hash != previous.hash:
            return False

        # Validação 3: Timestamp sequencial?
        if current.timestamp < previous.timestamp:
            return False

    return True
```

Esta função percorre toda a cadeia verificando três invariantes:
1. Cada bloco tem o hash correto para seus dados
2. Cada bloco aponta corretamente para o anterior
3. Os timestamps são cronológicos

**Sincronização (Merge):**
```python
def merge(self, other_chain_list):
    """Aceita outra chain apenas se for maior, válida e com mesmo genesis."""
    try:
        other = Blockchain.from_list(other_chain_list)
    except (ValueError, KeyError) as e:
        print(f"[SEGURANÇA] Chain rejeitada: {e}")
        return False

    # Validação 1: Mesmo genesis?
    if other.chain[0].hash != self.chain[0].hash:
        print("[SEGURANÇA] Genesis diferente")
        return False

    # Validação 2: Maior e válida?
    if len(other.chain) > len(self.chain) and other.is_valid():
        self.chain = other.chain
        return True
    return False
```

Esta função implementa a regra de consenso simples: **aceitar sempre a cadeia mais longa que seja válida e compatível**. Isso permite que peers novos ou desatualizados sincronizem com a rede.

---

### 2. multicast.py - Descoberta de Peers

Implementa descoberta automática de peers usando **multicast UDP**.

**Anunciante:**
```python
def multicast_announcer(port):
    """Anuncia presença na rede a cada 5 segundos."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    while True:
        message = f"PEER_ANNOUNCE:{port}".encode("utf-8")
        sock.sendto(message, (MULTICAST_GROUP, MULTICAST_PORT))
        time.sleep(5)
```

Cada peer envia periodicamente um anúncio para o grupo multicast `224.0.0.1:5004`, informando que está ativo e em qual porta está escutando.

**Ouvinte:**
```python
def multicast_listener(callback):
    """Escuta anúncios de outros peers."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", MULTICAST_PORT))

    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        data, addr = sock.recvfrom(1024)
        if data.decode("utf-8").startswith("PEER_ANNOUNCE:"):
            _, port = data.decode("utf-8").split(":")
            callback(addr[0], int(port))
```

Quando um anúncio é recebido, o callback é chamado com o IP e porta do peer descoberto, iniciando uma conexão TCP.

---

### 3. peer_blockchain_v2.py - Peer Normal

Este é o componente principal que integra todos os outros módulos.

#### Servidor TCP

Cada peer executa um servidor TCP que aceita conexões de outros peers:

```python
def start_server(chat_box):
    """Servidor TCP para receber peers."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen()

    while True:
        conn, addr = server.accept()
        peers[conn] = addr

        # Envia username imediatamente
        conn.sendall(f"USERNAME:{username}".encode("utf-8"))

        # Cria thread para gerenciar esta conexão
        threading.Thread(
            target=handle_peer,
            args=(conn, addr, chat_box),
            daemon=True
        ).start()
```

#### Cliente TCP

Conecta-se a peers descobertos:

```python
def connect_to_peer(ip, port, chat_box):
    """Conecta a um peer e sincroniza blockchain."""
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((ip, port))
    peers[conn] = (ip, port)

    # Envia username
    conn.sendall(f"USERNAME:{username}".encode("utf-8"))

    # Inicia thread para receber mensagens
    threading.Thread(
        target=handle_peer,
        args=(conn, (ip, port), chat_box),
        daemon=True
    ).start()

    # Pede sincronização da blockchain
    conn.sendall("BLOCKCHAIN_REQ".encode("utf-8"))
```

#### Protocolo de Comunicação

O sistema usa um protocolo textual simples:

1. **USERNAME:nome** - Troca de nomes de usuário
2. **BLOCKCHAIN_REQ** - Solicita blockchain completa
3. **BLOCKCHAIN_RESP\n{json}** - Responde com blockchain em JSON
4. **BLOCK:{json}** - Envia novo bloco para validação
5. Mensagens antigas sem prefixo (modo legado)

#### Handler de Peer

A função `handle_peer()` é executada em uma thread para cada conexão:

```python
def handle_peer(conn, addr, chat_box):
    """Thread para receber mensagens de um peer."""
    global messages, blockchain
    genesis_mismatch_count = 0
    max_genesis_mismatches = 3

    try:
        while True:
            data = conn.recv(8192).decode("utf-8")
            if not data:
                break

            # Filtro de mensagens concatenadas
            if "BLOCKCHAIN_REQ" in data and "BLOCKCHAIN_RESP" in data:
                if "BLOCKCHAIN_RESP\n" in data:
                    data = data[data.index("BLOCKCHAIN_RESP"):]
                else:
                    continue

            # USERNAME
            if data.startswith("USERNAME:"):
                peer_username = data.split(":", 1)[1]
                peer_names[conn] = peer_username
                update_peers_list()
                continue

            # BLOCKCHAIN_REQ
            if data == "BLOCKCHAIN_REQ":
                chain_data = json.dumps(blockchain.to_list())
                conn.sendall(f"BLOCKCHAIN_RESP\n{chain_data}".encode("utf-8"))
                continue

            # BLOCKCHAIN_RESP
            if data.startswith("BLOCKCHAIN_RESP"):
                try:
                    _, chain_json = data.split("\n", 1)
                    other_chain = json.loads(chain_json)

                    if blockchain.merge(other_chain):
                        print("[BLOCKCHAIN] Chain atualizada")
                        messages.clear()
                        for block in blockchain.chain[1:]:
                            messages.append(block.data)
                            insert_message(chat_box, block.data, "received")
                    else:
                        print("[BLOCKCHAIN] Chain rejeitada")

                        # Desconecta após 3 tentativas com genesis diferente
                        try:
                            other = Blockchain.from_list(other_chain)
                            if other.chain[0].hash != blockchain.chain[0].hash:
                                genesis_mismatch_count += 1
                                if genesis_mismatch_count >= max_genesis_mismatches:
                                    insert_message(chat_box, "⚠️ Genesis incompatível", "system")
                                    break
                        except:
                            pass

                except (ValueError, KeyError, json.JSONDecodeError) as e:
                    print(f"[SEGURANÇA] Chain malformada: {e}")
                    insert_message(chat_box, "⚠️ Chain malformada!", "system")
                continue

            # BLOCK
            if data.startswith("BLOCK:"):
                try:
                    _, block_json = data.split(":", 1)
                    block_dict = json.loads(block_json)

                    # Validação automática do hash no from_dict
                    try:
                        received_block = Block.from_dict(block_dict)
                    except ValueError as e:
                        insert_message(chat_box, f"⚠️ REJEITADO: {e}", "system")
                        continue

                    # Validação de encadeamento
                    if received_block.previous_hash != blockchain.get_latest_block().hash:
                        print("[SEGURANÇA] Previous hash não bate")
                        conn.sendall("BLOCKCHAIN_REQ".encode("utf-8"))
                        continue

                    # Validação de índice
                    if received_block.index != len(blockchain.chain):
                        insert_message(chat_box, "⚠️ Índice inválido", "system")
                        continue

                    # Validação de timestamp
                    if received_block.timestamp < blockchain.get_latest_block().timestamp:
                        insert_message(chat_box, "⚠️ Timestamp inválido", "system")
                        continue

                    # ✅ BLOCO VÁLIDO
                    blockchain.chain.append(received_block)
                    msg = received_block.data

                    if msg not in messages:
                        messages.append(msg)
                        print(f"[BLOCKCHAIN] ✓ Bloco #{received_block.index} validado")
                        insert_message(chat_box, msg, "received")
                        broadcast(data, origin=conn)

                except Exception as e:
                    print(f"[ERRO] Bloco malformado: {e}")
                    insert_message(chat_box, "⚠️ Bloco malformado!", "system")
                continue

    except Exception as e:
        print(f"[ERRO] handle_peer: {e}")
    finally:
        conn.close()
        peers.pop(conn, None)
        peer_names.pop(conn, None)
        update_peers_list()
```

Esta função é o coração do sistema, gerenciando todas as interações de rede e validações de segurança.

---

## Funcionamento da Blockchain

### Estrutura de Dados

A blockchain é essencialmente uma **lista encadeada** onde cada nó (bloco) contém:
- Dados (mensagem)
- Ponteiro criptográfico para o nó anterior (previous_hash)
- Identificador único (hash calculado de todos os campos)

```
Genesis Block          Bloco 1              Bloco 2
┌─────────────┐       ┌─────────────┐      ┌─────────────┐
│ Index: 0    │       │ Index: 1    │      │ Index: 2    │
│ Data: Gen   │◄──┐   │ Data: Msg1  │◄──┐  │ Data: Msg2  │
│ Prev: "0"   │   │   │ Prev: hash0 │   │  │ Prev: hash1 │
│ Hash: hash0 │   └───│ Hash: hash1 │   └──│ Hash: hash2 │
└─────────────┘       └─────────────┘      └─────────────┘
```

### Imutabilidade

A imutabilidade vem do **encadeamento criptográfico**:

1. Se você tentar modificar o Bloco 1:
   - O hash do Bloco 1 mudará
   - O Bloco 2 aponta para o hash antigo do Bloco 1
   - A validação detecta: `block2.previous_hash != block1.hash`
   - A cadeia se torna inválida

2. Se você modificar o Bloco 1 E recalcular seu hash:
   - O Bloco 2 ainda aponta para o hash antigo
   - Você precisa recalcular o Bloco 2 também
   - E o Bloco 3, e o 4, e assim por diante...
   - Mas os outros peers têm a cadeia original e rejeitarão sua versão

### Consenso Simplificado

Este sistema usa uma regra de consenso simples:
- **Aceitar sempre a cadeia válida mais longa**
- Não há proof-of-work ou mineração
- Em caso de conflito (fork), prevalece a maior

**Limitação**: Em uma rede real, isso é vulnerável a ataques. Blockchains de produção usam proof-of-work, proof-of-stake ou outros mecanismos de consenso mais sofisticados.

---

## Comunicação P2P

### Modelo de Rede

O sistema implementa um **full mesh network**, onde cada peer se conecta diretamente a todos os outros peers conhecidos:

```
     Peer A
    /  |  \
   /   |   \
  /    |    \
Peer B─┼─Peer C
  \    |    /
   \   |   /
    \  |  /
     Peer D
```

### Protocolo de Descoberta

1. **Anúncio**: Cada peer envia `PEER_ANNOUNCE:5555` via multicast a cada 5 segundos
2. **Descoberta**: Outros peers escutam o multicast e extraem IP + porta
3. **Conexão**: Peer ouvinte inicia conexão TCP com o peer anunciado
4. **Handshake**: Troca de usernames e sincronização de blockchain

### Broadcast de Mensagens

Quando um peer envia uma mensagem:

1. **Criação do Bloco**:
   ```python
   new_block = blockchain.add_block(f"[{username}]: {message}")
   ```

2. **Serialização**:
   ```python
   block_data = json.dumps(new_block.to_dict())
   ```

3. **Broadcast**:
   ```python
   broadcast(f"BLOCK:{block_data}")
   ```

4. **Recepção e Validação** por cada peer conectado

5. **Rebroadcast**: Se válido, cada peer repassa para seus outros peers

### Prevenção de Loops

Para evitar que mensagens circulem infinitamente:
- O parâmetro `origin` no broadcast evita reenviar para quem mandou
- O array `messages` mantém registro para evitar duplicatas:
  ```python
  if msg not in messages:
      messages.append(msg)
      broadcast(data, origin=conn)
  ```

---

## Mecanismos de Segurança

### 1. Validação em Múltiplas Camadas

Cada bloco recebido passa por **4 validações**:

#### Validação 1: Hash Correto
```python
received_block = Block.from_dict(block_dict)  # Lança exceção se hash inválido
```

Garante que os dados não foram adulterados em trânsito.

#### Validação 2: Encadeamento
```python
if received_block.previous_hash != blockchain.get_latest_block().hash:
    REJEITAR()
```

Garante que o bloco conecta corretamente com a cadeia existente.

#### Validação 3: Índice Sequencial
```python
if received_block.index != len(blockchain.chain):
    REJEITAR()
```

Previne inserção de blocos fora de ordem ou duplicados.

#### Validação 4: Timestamp Cronológico
```python
if received_block.timestamp < blockchain.get_latest_block().timestamp:
    REJEITAR()
```

Previne ataques de backdating.

### 2. Isolamento de Peers Maliciosos

Quando um peer tenta enviar blocos inválidos:

```
Peer Malicioso              Peer Honesto A            Peer Honesto B
      |                           |                         |
      |--- Bloco Inválido ------->|                         |
      |                      [VALIDAÇÃO]                    |
      |                           ❌                         |
      |                      REJEITADO                      |
      |                           |                         |
      |                      (não propaga)                  |
      |                           |                         |
      |                           |<--- Bloco Válido -------|
      |                      [VALIDAÇÃO]                    |
      |                           ✅                         |
      |                      ACEITO                         |
      |                           |                         |
```

O peer malicioso fica **isolado** pois seus blocos nunca passam na validação e não são propagados.

### 3. Sincronização Segura

Durante a sincronização, três verificações críticas:

1. **Genesis Matching**:
   ```python
   if other.chain[0].hash != self.chain[0].hash:
       return False
   ```

2. **Validação Completa**:
   ```python
   if other.is_valid():
       # Verifica TODOS os blocos
   ```

3. **Tratamento de Exceções**:
   ```python
   try:
       other = Blockchain.from_list(other_chain)
   except (ValueError, KeyError):
       # Chain malformada rejeitada
       return False
   ```

### 4. Propriedades Criptográficas do SHA-256

O SHA-256 fornece:
- **Determinismo**: Mesma entrada sempre gera mesma saída
- **Efeito Avalanche**: Mudança mínima na entrada muda completamente a saída
- **Pré-imagem**: Impossível reverter hash para obter dados originais
- **Resistência a Colisões**: Impossível (na prática) encontrar duas entradas com mesmo hash

---

## Peer Malicioso

### Objetivo Educacional

O peer malicioso existe para **demonstrar** que:
1. Adulteração de dados é facilmente detectável
2. Peers maliciosos são automaticamente isolados
3. A rede permanece segura mesmo com participantes desonestos

### Implementação da Infecção

```python
def adulterate_blockchain_interactive(chat_box):
    """Permite ao usuário modificar um bloco SEM recalcular o hash."""

    # Usuário seleciona um bloco
    block_index = selection[0] + 1
    new_data = new_content_entry.get().strip()

    # CRÍTICO: Modifica dados mas NÃO recalcula hash
    blockchain.chain[block_index].data = new_data
    # blockchain.chain[block_index].hash continua com valor antigo!

    # Marca como infectado
    INFECTED = True

    # Atualiza visualmente o chat
    messages[block_index - 1] = new_data
    # Reconstrói todo o chat para mostrar mensagem adulterada
```

### Consequências da Infecção

1. **Blockchain Local Inválida**:
   ```python
   blockchain.is_valid()  # Retorna False
   ```

2. **Auto-Isolamento**:
   ```python
   if INFECTED:
       # Bloqueia envio de mensagens
       # Bloqueia recepção de blocos
       # Rejeita sincronização
   ```

3. **Rejeição pela Rede**:
   - Se tentar enviar a blockchain corrompida, outros peers:
     - Detectam hashes inválidos no `from_dict()`
     - Rejeitam na validação `is_valid()`
     - Não propagam os blocos

### Demonstração de Segurança

Fluxo de um ataque:

```python
# Peer Malicioso modifica Bloco 2
blockchain.chain[2].data = "MENSAGEM FRAUDULENTA"
# Mas não recalcula: blockchain.chain[2].hash (ainda tem hash antigo)

# Tenta sincronizar com Peer Honesto
malicious_chain = blockchain.to_list()
send_to_peer(malicious_chain)

# No Peer Honesto:
for block_dict in received_chain:
    block = Block.from_dict(block_dict)  # ❌ ValueError!
    # Hash calculado: hash("...MENSAGEM FRAUDULENTA...")
    # Hash recebido: hash("...mensagem original...")
    # NÃO BATEM!

# Resultado: Chain rejeitada, ataque fracassou
```

---

## Fluxos de Dados

### Fluxo Completo: Envio de Mensagem

```
1. Usuário digita "Olá!" e pressiona Enter
   ↓
2. send_msg() é chamado
   ↓
3. Cria mensagem formatada: full_msg = "[Bruno]: Olá!"
   ↓
4. Adiciona à lista local: messages.append(full_msg)
   ↓
5. Cria novo bloco:
   new_block = blockchain.add_block(full_msg)
   - Index: 3
   - Timestamp: 1700000123.456
   - Data: "[Bruno]: Olá!"
   - Previous Hash: hash_do_bloco_2
   - Hash: SHA256(todos os campos acima)
   ↓
6. Serializa bloco: block_json = json.dumps(new_block.to_dict())
   ↓
7. Broadcast para todos os peers: broadcast(f"BLOCK:{block_json}")
   ↓
8. Cada peer conectado recebe "BLOCK:{...}"
   ↓
9. Peer receptor:
   a) Desserializa JSON
   b) Valida hash (from_dict)
   c) Valida previous_hash
   d) Valida index
   e) Valida timestamp
   f) Se todas passarem: adiciona à blockchain local
   g) Exibe mensagem no chat
   h) Rebroadcast para seus outros peers
```

### Fluxo de Sincronização

```
Peer Novo                          Peer Existente
    |                                    |
    |---------- Connect TCP ----------->|
    |                                    |
    |<--------- USERNAME:Alice ---------|
    |---------- USERNAME:Bob ----------->|
    |                                    |
    |-------- BLOCKCHAIN_REQ ----------->|
    |                                    |
    |                              [Serializa chain]
    |                                    |
    |<--- BLOCKCHAIN_RESP\n[{...}] ------|
    |                                    |
[Recebe chain]                          |
    |                                    |
[Valida genesis]                        |
    ✓ Genesis match                     |
    |                                    |
[Valida is_valid()]                     |
    ✓ Todos blocos válidos              |
    |                                    |
[Compara tamanho]                       |
    ✓ Chain recebida maior              |
    |                                    |
[Aceita chain]                          |
    ↓                                    |
blockchain.chain = other_chain          |
    ↓                                    |
[Reconstrói mensagens]                  |
    ↓                                    |
[Atualiza interface]                    |
    ↓                                    |
 ✅ Sincronizado!                        |
```

### Fluxo de Ataque (Falha)

```
Peer Malicioso                     Peer Honesto
    |                                  |
[Infecta bloco 2]                     |
    data = "HACK"                     |
    hash = (não recalculado)          |
    |                                  |
[Tenta sincronizar]                   |
    |                                  |
    |--- BLOCKCHAIN_RESP\n[{...}] --->|
    |                              [from_dict()]
    |                                  |
    |                           calc_hash = SHA256(2, ts, "HACK", prev)
    |                           recv_hash = (hash antigo)
    |                                  |
    |                           calc_hash != recv_hash
    |                                  |
    |                              ❌ ValueError!
    |                                  |
    |<------ (silenciosamente ---------|
    |         rejeitado)                |
    |                                  |
[Peer malicioso isolado]              |
```

---

## Conclusão

Este sistema demonstra de forma prática os conceitos fundamentais de:

1. **Blockchain**: Estrutura de dados imutável e encadeada
2. **Criptografia**: Uso de SHA-256 para validação
3. **Redes P2P**: Comunicação descentralizada
4. **Consenso Distribuído**: Regra da cadeia mais longa
5. **Segurança**: Detecção e isolamento de adulterações

