# 🚀 Guia Rápido de Execução

## Passo 1: Testar a Rede

Antes de executar o chat, teste se sua rede está configurada corretamente:

```bash
python test_network.py
```

✅ Se todos os testes passarem, prossiga para o Passo 2.  
❌ Se algum teste falhar, verifique firewall e configurações de rede.

---

## Passo 2: Executar o Chat

### Em uma máquina:

```bash
python peer_blockchain.py
```

### Em outra máquina (ou terminal):

```bash
python peer_blockchain.py
```

**Os peers se descobrirão automaticamente via multicast!**

---

## Passo 3: Testar a Comunicação

1. Digite seu nome de usuário quando solicitado
2. Aguarde alguns segundos para os peers se conectarem
3. No **painel lateral esquerdo**, você verá:
   - 👤 Seu usuário
   - 🟢 Peers conectados (quando outros entrarem)

4. Envie uma mensagem e observe:
   - Sua mensagem aparece em **verde** (direita)
   - No outro peer, aparece em **azul** (esquerda)

---

## Passo 4: Verificar a Blockchain

Clique no botão **"📊 Blockchain"** para ver:
- Total de blocos criados
- Status de validação da cadeia
- Detalhes de cada bloco (hash, dados, timestamp)

---

## Demonstrações para Apresentação

### Demo 1: Sincronização Automática
1. Abra o Peer A e envie 3 mensagens
2. Abra o Peer B
3. O Peer B receberá automaticamente todo o histórico via blockchain
4. Mostre em ambos clicando em "Blockchain"

### Demo 2: Imutabilidade
1. Mostre a blockchain funcionando normalmente
2. Explique que se alguém tentar alterar um bloco antigo...
3. A validação detectará (função `is_valid()`)

### Demo 3: Consenso Distribuído
1. Abra 3+ peers
2. Envie mensagens de diferentes peers
3. Mostre que todos têm a mesma blockchain sincronizada
4. Explique que a "cadeia mais longa válida" vence

---

## Troubleshooting Rápido

**Peers não aparecem na lista?**
- Aguarde 2-3 segundos (intervalo do multicast)
- Verifique se estão na mesma rede
- Execute `test_network.py`

**Mensagens não chegam?**
- Verifique o console por mensagens de erro
- Certifique-se que a blockchain está válida
- Reinicie todos os peers

**Auto-conexão acontecendo?**
- Isso foi corrigido no código
- Se persistir, cada peer deve ter IP diferente

---

## Estrutura Observável

Ao executar, você verá no **console**:

```
[SERVIDOR] Escutando em 0.0.0.0:5555
[CONECTADO] Peer 192.168.1.100:5555
[BLOCKCHAIN] Bloco #1 criado
[BLOCKCHAIN] Bloco #2 adicionado
```

Essas mensagens confirmam que tudo está funcionando! ✅

---

## Notas Importantes

- 📝 **Histórico volátil**: Existe apenas enquanto há peers conectados
- 🔗 **Blockchain em memória**: Não é salva em disco (propósito didático)
- 🌐 **Rede local**: Funciona melhor em LAN (mesma sub-rede)
- 👥 **Limite recomendado**: 3-10 peers para demonstração
