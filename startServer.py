import os
import multiprocessing
from blockchain import Blockchain, add_node_to_file, register_nodes_automatically
from time import sleep
import requests

def read_existing_ports():
    """Lê as portas dos nós registrados no arquivo nodes.txt"""
    if not os.path.exists('nodes.txt'):
        return []
    with open('nodes.txt', 'r') as file:
        nodes = file.readlines()
    return [node.strip().split(":")[-1] for node in nodes]  # Pega a porta de cada nó

def start_server(port=5000):
    """Função que inicializa o servidor na porta fornecida."""
    node_url = f"http://127.0.0.1:{port}"
    
    # Verifica se o arquivo de nós existe, se não, cria
    if not os.path.exists('nodes.txt'):
        with open('nodes.txt', 'w') as file:
            file.write(f"{node_url}\n")
    else:
        # Se o arquivo existe, registra o nó no arquivo
        add_node_to_file(node_url)  # Registra o nó no arquivo e nos outros nós
        register_nodes_automatically(node_url)  # Registra o nó atual nos outros

    # Inicia o servidor
    from blockchain import app
    app.run(host='127.0.0.1', port=port)

def all_servers_ready(ports):
    """Verifica se todos os servidores estão prontos (respondendo a uma requisição GET)."""
    for port in ports:
        node_url = f"http://127.0.0.1:{port}/chain"  # Rota comum de todos os servidores para verificar
        while True:
            try:
                response = requests.get(node_url)
                if response.status_code == 200:
                    print(f"Servidor na porta {port} está pronto.")
                    break
            except requests.exceptions.RequestException:
                print(f"Aguardando o servidor na porta {port}...")
            sleep(1)

def register_all_nodes(ports):
    """Registra todos os nós entre si após estarem prontos."""
    for i, port in enumerate(ports):
        node_url = f"http://127.0.0.1:{port}"
        for other_port in ports:
            if other_port != port:
                other_node_url = f"http://127.0.0.1:{other_port}"
                print(f"Registrando nó {node_url} em {other_node_url}")
                try:
                    response = requests.post(f"{other_node_url}/nodes/register", json={"nodes": [node_url]})
                    if response.status_code == 201:
                        print(f"Registro do nó {node_url} em {other_node_url} bem-sucedido.")
                    else:
                        print(f"Erro ao tentar registrar nó {node_url} em {other_node_url}.")
                except requests.exceptions.RequestException as e:
                    print(f"Erro ao tentar registrar nó {node_url} em {other_node_url}: {e}")

def start_multiple_servers():
    """Função para iniciar múltiplos servidores e garantir que todos estejam prontos antes de registrar entre si."""
    # Lê as portas dos nós registrados no arquivo
    registered_ports = read_existing_ports()
    
    # Define uma lista de portas padrão (5000 até 5005, por exemplo)
    default_ports = [5000, 5001, 5002, 5003, 5004,5005,5006,5007]
    
    # Adiciona qualquer nova porta ao conjunto de portas
    ports = set(registered_ports).union(default_ports)
    
    processes = []
    for port in ports:
        # Criar um processo para iniciar cada servidor
        process = multiprocessing.Process(target=start_server, args=(port,))
        processes.append(process)
        process.start()
        sleep(1)  # Atrasar o início de cada processo para garantir que as portas não colidam
    
    # Verificar se todos os servidores estão prontos antes de registrar os nós entre si
    all_servers_ready(list(ports))

    # Registrar todos os nós entre si após todos estarem prontos
    register_all_nodes(list(ports))

    # Espera todos os processos terminarem
    for process in processes:
        process.join()

if __name__ == '__main__':
    start_multiple_servers()