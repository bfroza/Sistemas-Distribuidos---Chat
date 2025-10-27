import hashlib
import json
import time


class Block:
    """Representa um bloco individual na blockchain."""
    
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data  # mensagem do chat
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """Calcula o hash SHA-256 do bloco."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def to_dict(self):
        """Converte o bloco para dicionário (para envio pela rede)."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }
    
    @staticmethod
    def from_dict(block_dict):
        """Cria um bloco a partir de um dicionário."""
        block = Block(
            block_dict["index"],
            block_dict["timestamp"],
            block_dict["data"],
            block_dict["previous_hash"]
        )
        # VALIDAÇÃO CRÍTICA: verifica se o hash recebido bate com o calculado
        if block.hash != block_dict["hash"]:
            raise ValueError(f"Hash inválido! Esperado: {block.hash[:16]}..., Recebido: {block_dict['hash'][:16]}...")
        return block


class Blockchain:
    """Blockchain simples para armazenar mensagens do chat."""
    
    def __init__(self):
        self.chain = [self.create_genesis_block()]
    
    def create_genesis_block(self):
        """Cria o primeiro bloco (gênesis) da blockchain."""
        # Timestamp fixo para garantir que todos os peers tenham o mesmo genesis
        return Block(0, 1700000000.0, "Genesis Block", "0")
    
    def get_latest_block(self):
        """Retorna o último bloco da chain."""
        return self.chain[-1]
    
    def add_block(self, data):
        """Adiciona um novo bloco com a mensagem."""
        previous_block = self.get_latest_block()
        new_block = Block(
            len(self.chain),
            time.time(),
            data,
            previous_block.hash
        )
        self.chain.append(new_block)
        return new_block
    
    def is_valid(self):
        """Verifica se a blockchain está íntegra."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Verifica se o hash está correto
            if current.hash != current.calculate_hash():
                return False

            # Verifica se está linkado ao bloco anterior
            if current.previous_hash != previous.hash:
                return False

            # Verifica se o timestamp é sequencial (não pode ser anterior ao bloco anterior)
            if current.timestamp < previous.timestamp:
                return False

        return True
    
    def to_list(self):
        """Converte a blockchain para lista de dicionários."""
        return [block.to_dict() for block in self.chain]
    
    @staticmethod
    def from_list(chain_list):
        """Cria uma blockchain a partir de uma lista."""
        blockchain = Blockchain()
        blockchain.chain = [Block.from_dict(b) for b in chain_list]
        return blockchain
    
    def merge(self, other_chain_list):
        """Mescla com outra chain (regra: aceita a maior válida com mesmo genesis)."""
        try:
            other = Blockchain.from_list(other_chain_list)
        except (ValueError, KeyError) as e:
            # Chain malformada ou com hashes inválidos
            print(f"[SEGURANÇA] Chain rejeitada durante from_list: {e}")
            return False

        # VALIDAÇÃO 1: Verifica se tem o mesmo bloco genesis
        if len(other.chain) == 0 or len(self.chain) == 0:
            return False

        if other.chain[0].hash != self.chain[0].hash:
            print("[SEGURANÇA] Chain rejeitada - bloco genesis diferente")
            return False

        # VALIDAÇÃO 2: Aceita apenas se for maior E válida
        if len(other.chain) > len(self.chain) and other.is_valid():
            self.chain = other.chain
            return True
        return False
