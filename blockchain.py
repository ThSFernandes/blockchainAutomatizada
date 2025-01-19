import hashlib
import json
import requests
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import os
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS


# Caminho do arquivo de nós
NODES_FILE = 'nodes.txt'

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Cria o bloco gênese
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Adiciona um novo nó à lista de nós
        :param address: Endereço do nó. Exemplo: 'http://192.168.0.5:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Aceita um URL sem esquema como '192.168.0.5:5000'
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('URL inválido')

    def valid_chain(self, chain):
        """
        Determina se uma blockchain é válida
        :param chain: Uma blockchain
        :return: True se for válida, False se não for
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # Verifica se o hash do bloco está correto
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Verifica se o Proof of Work está correto
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Algoritmo de consenso que resolve conflitos substituindo a nossa blockchain
        pela blockchain válida mais longa que contenha o bloco de consenso (hash mais votada e mais recente).
        :return: True se a nossa cadeia foi substituída, False caso contrário.
        """
        neighbours = self.nodes
        valid_hashes = {}
        all_chains = []  # Variável para armazenar todas as blockchains

        # Verifica as cadeias dos nós vizinhos e armazena as blockchains
        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    chain = response.json()['chain']
                    all_chains.append(chain)
                    chain_hashes = [self.hash(block) for block in chain]

                    # Armazena hashes, votos e posições
                    for index, hash_value in enumerate(chain_hashes):
                        if hash_value not in valid_hashes:
                            valid_hashes[hash_value] = {"votes": 1, "position": index}
                        else:
                            valid_hashes[hash_value]["votes"] += 1
                            valid_hashes[hash_value]["position"] = max(valid_hashes[hash_value]["position"], index)

            except Exception as e:
                print(f"Erro ao conectar com {node}: {e}")

        if not valid_hashes:
            # Sem hashes válidas
            return False

        # Encontrar a hash com mais votos
        max_votes = max(hash_data["votes"] for hash_data in valid_hashes.values())
        candidate_hashes = [
            hash_value
            for hash_value, hash_data in valid_hashes.items()
            if hash_data["votes"] == max_votes
        ]

        # Entre as hashes com mais votos, encontrar a mais recente (maior posição)
        most_valid_hash = max(
            candidate_hashes,
            key=lambda h: valid_hashes[h]["position"],
        )
        print(f"Hash mais validada: {most_valid_hash} com {max_votes} votos e posição {valid_hashes[most_valid_hash]['position']}.")

        # Encontrar todas as blockchains que contêm o bloco de consenso
        valid_chains = [
            chain for chain in all_chains
            if most_valid_hash in [self.hash(block) for block in chain]
        ]

        if not valid_chains:
            # Nenhuma blockchain contém o bloco de consenso
            return False

        # Escolher a blockchain mais longa ou com a hash do último bloco maior
        new_chain = max(valid_chains, key=lambda chain: (len(chain), self.hash(chain[-1])))

        # Substituir a cadeia local se a nova cadeia for mais longa ou se o último bloco for diferente
        if len(new_chain) > len(self.chain) or new_chain[-1] != self.chain[-1]:
            self.chain = new_chain
            print("Cadeia substituída pela mais longa e válida.")
            return True

        print("Cadeia atual é a mais longa e válida.")
        return False


    def new_block(self, proof, previous_hash):
        """
        Cria um novo bloco na blockchain
        :param proof: O proof dado pelo algoritmo Proof of Work
        :param previous_hash: O hash do bloco anterior
        :return: Novo bloco
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reseta a lista de transações
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Cria uma nova transação para ser adicionada ao próximo bloco
        :param sender: Endereço do remetente
        :param recipient: Endereço do destinatário
        :param amount: Quantidade
        :return: O índice do bloco que conterá essa transação
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Cria um hash SHA-256 de um bloco
        :param block: Bloco
        :return: Hash do bloco
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Algoritmo simples de Proof of Work:
         - Encontrar um número p' tal que hash(pp') contenha 4 zeros à frente
         - Onde p é o proof anterior, e p' é o novo proof
        :param last_block: O último bloco
        :return: Novo proof
        """
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Valida o proof
        :param last_proof: Proof anterior
        :param proof: Proof atual
        :param last_hash: Hash do último bloco
        :return: True se válido, False caso contrário
        """
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# Funções de leitura e gravação dos nós
def read_nodes_from_file():
    if not os.path.exists(NODES_FILE):
        return []

    with open(NODES_FILE, 'r') as file:
        return [line.strip() for line in file.readlines()]



# Inicializa o app Flask
app = Flask(__name__)
CORS(app)
node_identifier = str(uuid4()).replace('-', '')  # Identificador único para o nó
blockchain = Blockchain()

@app.route('/mine', methods=['GET'])
def mine():
    # Pegando o bloco atual (último bloco da cadeia)
    last_block = blockchain.last_block
    
    # Minerando o bloco
    proof = blockchain.proof_of_work(last_block)
    blockchain.new_transaction(sender="0", recipient=node_identifier, amount=1)

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    # Imprimindo o novo bloco
    print(f"Bloco minerado: {block}")

    response = {
        'message': "Novo bloco minerado",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200



@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Valores ausentes', 400

    # Verificar se a transação está sendo registrada corretamente
    print(f"Transação recebida: {values}")

    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])

    response = {'message': f'Transação será adicionada ao bloco {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Erro: Por favor forneça uma lista válida de nós", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'Novos nós foram adicionados',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/transactions', methods=['GET'])
def get_transactions():
    """
    Endpoint para exibir todas as transações na blockchain,
    incluindo o proof e o previous_hash do bloco anterior.
    """
    # Obtém o último bloco da cadeia
    last_block = blockchain.chain[-1] if blockchain.chain else None

    # Se houver um bloco, obtemos proof e previous_hash
    if last_block:
        proof = last_block['proof']
        previous_hash = last_block['previous_hash']
    else:
        proof = None
        previous_hash = None

    # Retorna a lista de transações na blockchain com proof e previous_hash
    response = {
        'transactions': blockchain.current_transactions,
        'total_transactions': len(blockchain.current_transactions),
        'proof': proof,
        'previous_hash': previous_hash
    }

    return jsonify(response), 200

@app.route('/transaction_auto', methods=['POST'])
def transaction_and_mine():
    values = request.get_json()

    # Verificar se os campos essenciais estão presentes
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Valores ausentes', 400

    # Adicionar a nova transação
    sender = values['sender']
    recipient = values['recipient']
    amount = values['amount']

    # Cria a nova transação
    blockchain.new_transaction(sender, recipient, amount)
    
    # Minerar o bloco
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)
    previous_hash = blockchain.hash(last_block)
    
    # Cria o novo bloco minerado
    block = blockchain.new_block(proof, previous_hash)

    # Log para verificar o bloco minerado
    print(f"Bloco minerado: {block}")

    # Resolver conflitos com os outros nós registrados
    for node in blockchain.nodes:
        try:
            # Chama o endpoint /nodes/resolve nos outros nós para resolver os conflitos
            print(f"Resolvendo conflito com o nó {node}")
            response = requests.get(f'http://{node}/nodes/resolve')
            if response.status_code == 200:
                print(f"Conflito resolvido no nó {node}")
            else:
                print(f"Erro ao resolver conflito no nó {node}: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Erro ao tentar resolver conflito no nó {node}: {str(e)}")

    # Resposta com os detalhes do novo bloco minerado
    response = {
        'message': "Novo bloco minerado e transação adicionada!",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }

    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Nossa cadeia foi substituída',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Nossa cadeia é autoritativa',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


def add_node_to_file(node_url):
    """
    Adiciona o nó à lista de nós no arquivo `nodes.txt`.
    """
    with open('nodes.txt', 'a') as file:
        file.write(f"{node_url}\n")
    print(f"Nó {node_url} registrado no arquivo de nós.")


def register_nodes_automatically(node_url):
    """
    Registra este nó automaticamente nos outros nós existentes.
    """
    # Lê os nós do arquivo
    try:
        with open('nodes.txt', 'r') as file:
            nodes = file.readlines()
        
        for node in nodes:
            node = node.strip()  # Remover possíveis espaços extras ou quebras de linha
            if node != node_url:  # Não tentar registrar o nó atual em si mesmo
                try:
                    # Garantir que a URL está corretamente formatada com "http://"
                    if not node.startswith('http://'):
                        node = 'http://' + node
                    
                    response = requests.post(f'{node}/nodes/register', json={"nodes": [node_url]})
                    if response.status_code == 201:
                        print(f"Registro do nó {node_url} em {node} bem-sucedido.")
                    else:
                        print(f"Erro ao registrar nó {node_url} em {node}: {response.text}")
                except requests.exceptions.RequestException as e:
                    print(f"Erro ao tentar registrar nó {node_url} em {node}: {str(e)}")
    except FileNotFoundError:
        print("Arquivo de nós não encontrado. Certifique-se de que o arquivo 'nodes.txt' existe.")

# novas


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='Porta para escutar')
    args = parser.parse_args()
    port = args.port

    # Registra os nós automaticamente ao iniciar o servidor
    register_nodes_automatically(f'http://127.0.0.1:{port}')

    app.run(host='127.0.0.1', port=port)



