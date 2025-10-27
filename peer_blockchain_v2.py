import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
import json
import time
from multicast import multicast_announcer, multicast_listener
from blockchain import Blockchain

PORT = 5555
messages = []        # histórico local
peers = {}           # {conn: (ip, port)}
peer_names = {}      # {conn: username} - nomes dos peers
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
        
        # Filtra apenas peers com porta diferente de 5555 (portas efêmeras de clientes)
        valid_peers = [(conn, ip, port) for conn, (ip, port) in peers.items() if port != 5555]
        
        if valid_peers:
            peers_listbox.insert(tk.END, f"🟢 Conectados ({len(valid_peers)}):")
            for conn, ip, port in valid_peers:
                peer_name = peer_names.get(conn, "Conectando...")
                # Mostra nome e IP com porta real (efêmera)
                peers_listbox.insert(tk.END, f"   {peer_name} ({ip}:{port})")
        else:
            peers_listbox.insert(tk.END, "⚪ Nenhum peer conectado")


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
    genesis_mismatch_count = 0  # Contador de tentativas de sincronização falhadas
    max_genesis_mismatches = 3  # Máximo de tentativas antes de desistir

    try:
        while True:
            data = conn.recv(8192).decode("utf-8")
            if not data:
                break

            # IMPORTANTE: Ignora completamente mensagens que contenham protocolos misturados
            # Isso evita que "BLOCKCHAIN_REQBLOCKCHAIN_RESP..." entre no chat
            if "BLOCKCHAIN_REQ" in data and "BLOCKCHAIN_RESP" in data:
                # Mensagens concatenadas - processa apenas BLOCKCHAIN_RESP
                if "BLOCKCHAIN_RESP\n" in data:
                    data = data[data.index("BLOCKCHAIN_RESP"):]
                else:
                    continue

            # Troca de nome de usuário
            if data.startswith("USERNAME:"):
                peer_username = data.split(":", 1)[1]
                peer_names[conn] = peer_username
                update_peers_list()
                print(f"[PEER] {peer_username} conectado de {addr}")
                continue

            # BLOCKCHAIN: sincronização de blockchain
            if data == "BLOCKCHAIN_REQ":
                # Peer pediu a blockchain (silencioso - não loga)
                chain_data = json.dumps(blockchain.to_list())
                conn.sendall(f"BLOCKCHAIN_RESP\n{chain_data}".encode("utf-8"))
                continue

            if data.startswith("BLOCKCHAIN_RESP"):
                # Recebeu blockchain de outro peer
                try:
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
                    else:
                        # Apenas loga sem mostrar no chat
                        print("[BLOCKCHAIN] Chain recebida rejeitada (inválida, menor ou genesis diferente)")

                        # Se rejeitou por genesis diferente, desconecta após algumas tentativas
                        try:
                            other = Blockchain.from_list(other_chain)
                            if other.chain[0].hash != blockchain.chain[0].hash:
                                genesis_mismatch_count += 1
                                print(f"[AVISO] Genesis diferente detectado ({genesis_mismatch_count}/{max_genesis_mismatches})")
                                if genesis_mismatch_count >= max_genesis_mismatches:
                                    insert_message(chat_box,
                                                 f"⚠️ Peer {addr[0]} tem blockchain incompatível (genesis diferente). Desconectando...",
                                                 "system")
                                    print(f"[BLOCKCHAIN] Desconectando peer {addr} - genesis incompatível")
                                    break
                        except:
                            pass

                except (ValueError, KeyError, json.JSONDecodeError) as e:
                    print(f"[SEGURANÇA] Blockchain malformada rejeitada: {e}")
                    insert_message(chat_box,
                                 "⚠️ REJEITADO: Blockchain malformada ou com hashes inválidos!",
                                 "system")
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

            # Recebe BLOCO com validação criptográfica
            if data.startswith("BLOCK:"):
                # VALIDAÇÃO 0: Verifica se nossa blockchain está íntegra
                if not blockchain.is_valid():
                    insert_message(chat_box,
                                 "⚠️ BLOCKCHAIN LOCAL CORROMPIDA! Rejeitando novos blocos.",
                                 "system")
                    print("[SEGURANÇA] Blockchain local inválida! Rejeitando bloco.")
                    continue

                try:
                    _, block_json = data.split(":", 1)
                    block_dict = json.loads(block_json)
                    from blockchain import Block

                    # Block.from_dict agora valida o hash automaticamente
                    try:
                        received_block = Block.from_dict(block_dict)
                    except ValueError as e:
                        insert_message(chat_box,
                                     f"⚠️ REJEITADO: {str(e)}",
                                     "system")
                        print(f"[SEGURANÇA] Bloco rejeitado - {e}")
                        continue

                    # VALIDAÇÃO 2: Conecta com nossa blockchain?
                    if received_block.previous_hash != blockchain.get_latest_block().hash:
                        # Apenas loga sem mostrar no chat para não poluir a interface
                        print(f"[SEGURANÇA] Bloco rejeitado - previous_hash não bate")
                        print(f"  Esperado: {blockchain.get_latest_block().hash[:16]}...")
                        print(f"  Recebido: {received_block.previous_hash[:16]}...")
                        print(f"[BLOCKCHAIN] Pedindo sincronização...")
                        conn.sendall("BLOCKCHAIN_REQ".encode("utf-8"))
                        continue

                    # VALIDAÇÃO 3: Índice sequencial correto?
                    if received_block.index != len(blockchain.chain):
                        insert_message(chat_box,
                                     f"⚠️ REJEITADO: Índice errado (esperado {len(blockchain.chain)}, recebido {received_block.index})",
                                     "system")
                        print(f"[SEGURANÇA] Bloco rejeitado - índice inválido")
                        continue

                    # VALIDAÇÃO 4: Timestamp é sequencial?
                    if received_block.timestamp < blockchain.get_latest_block().timestamp:
                        insert_message(chat_box,
                                     f"⚠️ REJEITADO: Timestamp inválido (anterior ao bloco anterior)",
                                     "system")
                        print(f"[SEGURANÇA] Bloco rejeitado - timestamp anterior ao último bloco")
                        continue

                    # ✅ BLOCO VÁLIDO - Adiciona à blockchain
                    blockchain.chain.append(received_block)
                    msg = received_block.data

                    if msg not in messages:
                        messages.append(msg)
                        print(f"[BLOCKCHAIN] ✓ Bloco #{received_block.index} VALIDADO e adicionado")
                        insert_message(chat_box, msg, "received")
                        broadcast(data, origin=conn)

                except Exception as e:
                    print(f"[ERRO] Falha ao processar bloco: {e}")
                    insert_message(chat_box,
                                 "⚠️ REJEITADO: Bloco malformado!",
                                 "system")
                continue

            # Mensagem normal (MODO LEGADO - compatibilidade retroativa)
            if data not in messages:
                # VALIDA A BLOCKCHAIN ANTES DE ACEITAR NOVA MENSAGEM
                if not blockchain.is_valid():
                    insert_message(chat_box,
                                 "⚠️ BLOCKCHAIN CORROMPIDA! Rejeitando novas mensagens até sincronizar.",
                                 "system")
                    print("[SEGURANÇA] Blockchain inválida! Rejeitando mensagem.")
                    continue

                messages.append(data)
                # BLOCKCHAIN: adiciona mensagem à blockchain
                blockchain.add_block(data)
                print(f"[BLOCKCHAIN] Bloco #{len(blockchain.chain)-1} adicionado (modo legado)")

                insert_message(chat_box, data, "received")
                broadcast(data, origin=conn)
    except Exception as e:
        print(f"[ERRO] handle_peer: {e}")
    finally:
        conn.close()
        peers.pop(conn, None)
        peer_names.pop(conn, None)
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
        
        # Envia o nome de usuário para o peer que conectou
        try:
            conn.sendall(f"USERNAME:{username}".encode("utf-8"))
        except:
            pass
        
        update_peers_list()  # Atualiza lista visual
        threading.Thread(
            target=handle_peer, args=(conn, addr, chat_box), daemon=True
        ).start()


def connect_to_peer(ip, port, chat_box):
    """Conecta em um peer existente e sincroniza blockchain."""
    # Evita conectar no mesmo peer duas vezes
    for conn, (peer_ip, peer_port) in peers.items():
        if peer_ip == ip and peer_port == port:
            return
    
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((ip, port))
        peers[conn] = (ip, port)
        known_peers.add((ip, port))  # Adiciona aos conhecidos
        
        # Envia o nome de usuário para o peer
        try:
            conn.sendall(f"USERNAME:{username}".encode("utf-8"))
            time.sleep(0.1)  # Pequeno delay para não misturar mensagens
        except:
            pass
        
        update_peers_list()  # Atualiza lista visual
        
        threading.Thread(
            target=handle_peer, args=(conn, (ip, port), chat_box), daemon=True
        ).start()

        # BLOCKCHAIN: pede blockchain ao invés de histórico simples
        time.sleep(0.1)  # Pequeno delay
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
            new_block = blockchain.add_block(full_msg)
            print(f"[BLOCKCHAIN] Bloco #{len(blockchain.chain)-1} criado")

            insert_message(chat_box, full_msg, "sent")

            # Envia o BLOCO completo ao invés da mensagem pura
            block_data = json.dumps(new_block.to_dict())
            broadcast(f"BLOCK:{block_data}")

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