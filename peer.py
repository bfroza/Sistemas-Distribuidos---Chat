import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
import json
from multicast import multicast_announcer, multicast_listener
from blockchain import Blockchain

PORT = 5555
messages = []        # histórico local
peers = {}           # {conn: (ip, port)}
username = None      # nome do usuário local
blockchain = Blockchain()  # BLOCKCHAIN: cadeia de blocos
known_peers = set()  # {(ip, port)} - peers descobertos
peers_listbox = None  # Referência para o listbox de peers


def update_peers_list():
    """Atualiza a lista visual de peers conectados."""
    if peers_listbox:
        peers_listbox.delete(0, tk.END)
        peers_listbox.insert(tk.END, f"👤 Você: {username}")
        peers_listbox.insert(tk.END, "─" * 25)
        
        if peers:
            for conn, (ip, port) in peers.items():
                peers_listbox.insert(tk.END, f"🟢 {ip}:{port}")
        else:
            peers_listbox.insert(tk.END, "⚪ Nenhum peer conectado")
        
        # Mostra peers descobertos mas não conectados
        connected_addrs = set(peers.values())
        discovered_only = known_peers - connected_addrs
        if discovered_only:
            peers_listbox.insert(tk.END, "")
            peers_listbox.insert(tk.END, "📡 Descobertos:")
            for ip, port in discovered_only:
                peers_listbox.insert(tk.END, f"⚪ {ip}:{port}")


def broadcast(msg, origin=None):
    """Envia mensagem para todos os peers conectados (menos quem enviou)."""
    for conn in list(peers.keys()):
        if conn == origin:
            continue
        try:
            conn.sendall(msg.encode("utf-8"))
        except:
            conn.close()
            peers.pop(conn, None)


def handle_peer(conn, addr, chat_box):
    """Thread para receber mensagens de um peer."""
    global messages, blockchain
    try:
        while True:
            data = conn.recv(8192).decode("utf-8")
            if not data:
                break

            # BLOCKCHAIN: sincronização de blockchain
            if data == "BLOCKCHAIN_REQ":
                # Peer pediu a blockchain
                chain_data = json.dumps(blockchain.to_list())
                conn.sendall(f"BLOCKCHAIN_RESP\n{chain_data}".encode("utf-8"))
                continue

            if data.startswith("BLOCKCHAIN_RESP"):
                # Recebeu blockchain de outro peer
                _, chain_json = data.split("\n", 1)
                other_chain = json.loads(chain_json)
                
                # Mescla com a chain local (aceita a maior válida)
                if blockchain.merge(other_chain):
                    print("[BLOCKCHAIN] Chain atualizada de outro peer")
                    # Reconstrói o histórico de mensagens
                    messages.clear()
                    for block in blockchain.chain[1:]:  # pula genesis
                        messages.append(block.data)
                        insert_message(chat_box, block.data, "received")
                continue

            if data == "HISTORY_REQ":
                # Novo peer pediu histórico (mantido por compatibilidade)
                history = "\n".join(messages)
                conn.sendall(f"HISTORY_RESP\n{history}".encode("utf-8"))
                continue

            if data.startswith("HISTORY_RESP"):
                # Recebeu histórico de outro peer
                _, history = data.split("\n", 1)
                for msg in history.split("\n"):
                    if msg and msg not in messages:
                        messages.append(msg)
                        insert_message(chat_box, msg, "received")
                continue

            # Mensagem normal
            if data not in messages:
                messages.append(data)
                # BLOCKCHAIN: adiciona mensagem à blockchain
                blockchain.add_block(data)
                print(f"[BLOCKCHAIN] Bloco #{len(blockchain.chain)-1} adicionado")
                
                insert_message(chat_box, data, "received")
                broadcast(data, origin=conn)
    except:
        pass
    finally:
        conn.close()
        peers.pop(conn, None)
        update_peers_list()  # Atualiza lista ao desconectar


def start_server(chat_box):
    """Servidor TCP para receber peers."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen()
    print(f"[SERVIDOR] Escutando em 0.0.0.0:{PORT}")

    while True:
        conn, addr = server.accept()
        peers[conn] = addr
        known_peers.add(addr)  # Adiciona aos conhecidos
        update_peers_list()  # Atualiza lista visual
        threading.Thread(
            target=handle_peer, args=(conn, addr, chat_box), daemon=True
        ).start()


def connect_to_peer(ip, port, chat_box):
    """Conecta em um peer existente e sincroniza blockchain."""
    # Evita conectar em si mesmo (verifica se é o próprio IP)
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        if ip in ['127.0.0.1', 'localhost', local_ip] and port == PORT:
            return
    except:
        pass
    
    # Evita conectar no mesmo peer duas vezes
    for conn, (peer_ip, peer_port) in peers.items():
        if peer_ip == ip and peer_port == port:
            return
    
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((ip, port))
        peers[conn] = (ip, port)
        known_peers.add((ip, port))  # Adiciona aos conhecidos
        update_peers_list()  # Atualiza lista visual
        
        threading.Thread(
            target=handle_peer, args=(conn, (ip, port), chat_box), daemon=True
        ).start()

        # BLOCKCHAIN: pede blockchain ao invés de histórico simples
        conn.sendall("BLOCKCHAIN_REQ".encode("utf-8"))
        print(f"[CONECTADO] Peer {ip}:{port}")
    except Exception as e:
        print(f"[ERRO] Não conectou a {ip}:{port} → {e}")


def insert_message(chat_box, msg, msg_type):
    """Insere mensagens com estilo diferente no chat_box."""
    chat_box.config(state="normal")
    if msg_type == "sent":
        chat_box.insert(tk.END, msg + "\n", "right")
    elif msg_type == "received":
        chat_box.insert(tk.END, msg + "\n", "left")
    elif msg_type == "system":
        chat_box.insert(tk.END, msg + "\n", "center")
    chat_box.config(state="disabled")
    chat_box.see(tk.END)


def show_blockchain_info():
    """Mostra informações da blockchain em uma janela popup."""
    info_window = tk.Toplevel()
    info_window.title("Blockchain Info")
    info_window.geometry("500x400")
    
    text = scrolledtext.ScrolledText(info_window, wrap=tk.WORD, width=60, height=20)
    text.pack(padx=10, pady=10)
    
    # Informações da blockchain
    text.insert(tk.END, f"═══ BLOCKCHAIN INFO ═══\n\n")
    text.insert(tk.END, f"Total de blocos: {len(blockchain.chain)}\n")
    text.insert(tk.END, f"Blockchain válida: {'✓ SIM' if blockchain.is_valid() else '✗ NÃO'}\n\n")
    
    text.insert(tk.END, "═══ BLOCOS ═══\n\n")
    
    for block in blockchain.chain:
        text.insert(tk.END, f"Bloco #{block.index}\n")
        text.insert(tk.END, f"  Hash: {block.hash[:16]}...\n")
        text.insert(tk.END, f"  Hash Anterior: {block.previous_hash[:16]}...\n")
        text.insert(tk.END, f"  Dados: {block.data[:50]}...\n" if len(block.data) > 50 else f"  Dados: {block.data}\n")
        text.insert(tk.END, f"  Timestamp: {block.timestamp:.2f}\n")
        text.insert(tk.END, "\n")
    
    text.config(state="disabled")


def on_peer_discovered(ip, port, chat_box):
    """Callback quando um peer é descoberto via multicast."""
    known_peers.add((ip, port))
    update_peers_list()
    connect_to_peer(ip, port, chat_box)


def start_gui():
    global username, peers_listbox
    root = tk.Tk()
    root.withdraw()  # esconde janela enquanto pergunta nome

    username = simpledialog.askstring("Usuário", "Digite seu nome de usuário:", parent=root)
    if not username:
        username = "Anônimo"

    root.deiconify()
    root.title(f"P2P Chat + Blockchain - {username}")
    root.geometry("800x500")

    # Frame principal com dois painéis
    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Painel esquerdo - Lista de peers
    left_frame = tk.Frame(main_frame, width=200)
    left_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 5))

    peers_label = tk.Label(left_frame, text="🌐 Peers Conectados", font=("Arial", 10, "bold"))
    peers_label.pack(pady=(0, 5))

    peers_listbox = tk.Listbox(left_frame, width=25, height=20, font=("Courier", 9))
    peers_listbox.pack(fill=tk.BOTH, expand=True)

    # Painel direito - Chat
    right_frame = tk.Frame(main_frame)
    right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    chat_box = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, width=50, height=20, state="disabled")
    chat_box.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

    # estilos
    chat_box.tag_config("left", justify="left", foreground="blue")
    chat_box.tag_config("right", justify="right", foreground="green")
    chat_box.tag_config("center", justify="center", foreground="gray", font=("Arial", 8, "italic"))

    # Frame para entrada e botões
    bottom_frame = tk.Frame(right_frame)
    bottom_frame.pack(fill=tk.X)

    entry = tk.Entry(bottom_frame, width=40)
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def send_msg(event=None):
        msg = entry.get().strip()
        if msg:
            full_msg = f"[{username}]: {msg}"
            messages.append(full_msg)
            
            # BLOCKCHAIN: adiciona mensagem à blockchain
            blockchain.add_block(full_msg)
            print(f"[BLOCKCHAIN] Bloco #{len(blockchain.chain)-1} criado")
            
            insert_message(chat_box, full_msg, "sent")
            broadcast(full_msg)
            entry.delete(0, tk.END)

    send_btn = tk.Button(bottom_frame, text="Enviar", command=send_msg)
    send_btn.pack(side=tk.LEFT, padx=5)

    # BLOCKCHAIN: botão para visualizar blockchain
    blockchain_btn = tk.Button(bottom_frame, text="📊 Blockchain", command=show_blockchain_info)
    blockchain_btn.pack(side=tk.LEFT, padx=5)

    entry.bind("<Return>", send_msg)

    # Atualiza lista inicial de peers
    update_peers_list()

    # Inicia threads de rede
    threading.Thread(target=start_server, args=(chat_box,), daemon=True).start()
    threading.Thread(target=multicast_announcer, args=(PORT,), daemon=True).start()
    threading.Thread(
        target=multicast_listener, args=(lambda ip, port: on_peer_discovered(ip, port, chat_box),), daemon=True
    ).start()

    root.mainloop()


if __name__ == "__main__":
    start_gui()
