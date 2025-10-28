import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import json
import time
from multicast import multicast_announcer, multicast_listener
from blockchain import Blockchain

PORT = 5555
messages = []
peers = {}
peer_names = {}
username = None
blockchain = Blockchain()
known_peers = set()
peers_listbox = None

# ⚠️ MODO MALICIOSO (Inicia DESATIVADO) ⚠️
MALICIOUS_MODE = False
INFECTED = False  # Flag para indicar se já foi infectado


def update_peers_list():
    """Atualiza a lista visual de peers conectados."""
    if peers_listbox:
        peers_listbox.delete(0, tk.END)
        if INFECTED:
            peers_listbox.insert(tk.END, f"😈 Você: {username} [INFECTADO]")
        else:
            peers_listbox.insert(tk.END, f"👤 Você: {username}")
        peers_listbox.insert(tk.END, "─" * 25)

        if peers:
            peers_listbox.insert(tk.END, f"🟢 Conectados ({len(peers)}):")
            for conn in peers.keys():
                peer_name = peer_names.get(conn, "Conectando...")
                peers_listbox.insert(tk.END, f"   {peer_name}")
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


def corrupt_blockchain_permanently():
    """
    Corrompe a blockchain de forma permanente modificando dados sem recalcular hashes.
    Isso torna a blockchain inválida para sempre.
    """
    print("\n" + "="*60)
    print("🦠 BLOCKCHAIN CORROMPIDA PERMANENTEMENTE 🦠")
    print("="*60)
    print("A blockchain agora está QUEBRADA e será rejeitada por todos os peers.")
    print("="*60 + "\n")


def adulterate_blockchain_interactive(chat_box):
    """Abre janela para o usuário escolher como adulterar a blockchain."""
    if len(blockchain.chain) <= 1:
        messagebox.showwarning("Aviso", "Blockchain vazia! Não há blocos para modificar.")
        return False

    # Janela de seleção
    adulterate_window = tk.Toplevel()
    adulterate_window.title("🦠 INFECTAR BLOCKCHAIN")
    adulterate_window.geometry("600x500")
    adulterate_window.configure(bg="#1a0000")

    tk.Label(adulterate_window, text="🦠 MODO INFECÇÃO 🦠",
             font=("Arial", 16, "bold"), bg="#1a0000", fg="red").pack(pady=10)

    tk.Label(adulterate_window,
             text="⚠️ ATENÇÃO: Isso irá MODIFICAR A LÓGICA DA BLOCKCHAIN! ⚠️",
             font=("Arial", 9, "bold"), bg="#1a0000", fg="yellow", wraplength=550).pack(pady=5)

    tk.Label(adulterate_window,
             text="A blockchain passará a aceitar blocos inválidos e não validar corretamente.",
             font=("Arial", 9), bg="#1a0000", fg="orange", wraplength=550).pack(pady=2)

    # Frame para lista de blocos
    list_frame = tk.Frame(adulterate_window, bg="#1a0000")
    list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    tk.Label(list_frame, text="Selecione o bloco para modificar:",
             font=("Arial", 10, "bold"), bg="#1a0000", fg="orange").pack(anchor="w")

    # Listbox com scrollbar
    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    blocks_listbox = tk.Listbox(list_frame, width=70, height=8,
                                font=("Courier", 9), bg="#330000", fg="white",
                                yscrollcommand=scrollbar.set)
    blocks_listbox.pack(fill=tk.BOTH, expand=True)
    scrollbar.config(command=blocks_listbox.yview)

    # Preenche lista de blocos (exceto Genesis)
    for i, block in enumerate(blockchain.chain):
        if i == 0:  # Pula Genesis
            continue
        preview = block.data[:60] + "..." if len(block.data) > 60 else block.data
        blocks_listbox.insert(tk.END, f"Bloco #{block.index} - {preview}")

    # Campo para novo conteúdo
    tk.Label(adulterate_window, text="Digite o novo conteúdo:",
             font=("Arial", 10, "bold"), bg="#1a0000", fg="orange").pack(pady=(10, 5))

    new_content_entry = tk.Entry(adulterate_window, width=60,
                                 font=("Arial", 10), bg="#330000", fg="red")
    new_content_entry.pack(pady=5)
    new_content_entry.insert(0, "[MENSAGEM ADULTERADA PELO HACKER]")

    # Campo para timestamp (opcional)
    timestamp_frame = tk.Frame(adulterate_window, bg="#1a0000")
    timestamp_frame.pack(pady=5)

    tk.Label(timestamp_frame, text="Timestamp (deixe vazio para manter):",
             font=("Arial", 10, "bold"), bg="#1a0000", fg="orange").pack(side=tk.LEFT, padx=(0, 10))

    timestamp_entry = tk.Entry(timestamp_frame, width=20,
                               font=("Arial", 10), bg="#330000", fg="red")
    timestamp_entry.pack(side=tk.LEFT)

    result = {"modified": False}

    def apply_infection():
        selection = blocks_listbox.curselection()
        if not selection:
            messagebox.showerror("Erro", "Selecione um bloco para modificar!")
            return

        # O índice selecionado + 1 (porque pulamos o Genesis)
        block_index = selection[0] + 1
        new_data = new_content_entry.get().strip()

        if not new_data:
            messagebox.showerror("Erro", "Digite um novo conteúdo!")
            return

        # Aplica a modificação nos dados
        global INFECTED, MALICIOUS_MODE, messages
        original_data = blockchain.chain[block_index].data
        original_timestamp = blockchain.chain[block_index].timestamp
        original_hash = blockchain.chain[block_index].hash

        # Modifica os dados - o hash será recalculado automaticamente
        blockchain.chain[block_index].data = new_data

        # Modifica timestamp se fornecido
        timestamp_str = timestamp_entry.get().strip()
        if timestamp_str:
            try:
                new_timestamp = float(timestamp_str)
                blockchain.chain[block_index].timestamp = new_timestamp
            except:
                messagebox.showerror("Erro", "Timestamp inválido! Use formato numérico (ex: 1761592522.68)")
                return

        # RECALCULA os hashes de todos os blocos seguintes
        # para manter o encadeamento correto
        blockchain.recalculate_from(block_index + 1)

        INFECTED = True
        MALICIOUS_MODE = True

        # Atualiza a mensagem no array de mensagens
        if block_index - 1 < len(messages):  # -1 porque messages não inclui genesis
            messages[block_index - 1] = new_data

        # ATUALIZA O CHAT - reconstrói todas as mensagens
        chat_box.config(state="normal")
        chat_box.delete(1.0, tk.END)  # Limpa o chat

        # Reinsere todas as mensagens
        for msg in messages:
            if msg.startswith(f"[{username}]"):
                # Mensagens próprias
                chat_box.insert(tk.END, msg + "\n", "right")
            else:
                # Mensagens de outros
                chat_box.insert(tk.END, msg + "\n", "left")

        chat_box.config(state="disabled")
        chat_box.see(tk.END)

        corrupt_blockchain_permanently()

        print(f"\nBloco #{block_index} CORROMPIDO:")
        print(f"  Dados originais: {original_data}")
        print(f"  Novos dados: {new_data}")
        print(f"  Timestamp original: {original_timestamp}")
        print(f"  Novo timestamp: {blockchain.chain[block_index].timestamp}")
        print(f"  Hash armazenado: {original_hash[:16]}...")
        print(f"  Hash que deveria ser: {blockchain.chain[block_index].calculate_hash()[:16]}...")
        print(f"  Hashes são iguais? {blockchain.chain[block_index].hash == blockchain.chain[block_index].calculate_hash()}")
        print(f"  Blockchain válida? {blockchain.is_valid()}")
        print(f"  INFECTED flag: {INFECTED}")
        print(f"  MALICIOUS_MODE flag: {MALICIOUS_MODE}")
        print()

        result["modified"] = True
        messagebox.showinfo("Sucesso!",
                          f"✓ BLOCO #{block_index} CORROMPIDO!\n"
                          f"✓ Dados modificados sem recalcular hash\n"
                          f"✓ Blockchain agora é INVÁLIDA\n\n"
                          f"⚠️ Outros peers irão REJEITAR\n"
                          f"⚠️ Peer ISOLADO da rede\n"
                          f"⚠️ is_valid() retorna: {blockchain.is_valid()}")
        adulterate_window.destroy()

    # Botões
    btn_frame = tk.Frame(adulterate_window, bg="#1a0000")
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="🦠 CORROMPER BLOCO", command=apply_infection,
             font=("Arial", 12, "bold"), bg="red", fg="white",
             width=18).pack(side=tk.LEFT, padx=5)

    tk.Button(btn_frame, text="Cancelar", command=adulterate_window.destroy,
             font=("Arial", 12), bg="#660000", fg="white",
             width=15).pack(side=tk.LEFT, padx=5)

    adulterate_window.wait_window()
    return result["modified"]


def handle_peer(conn, addr, chat_box):
    """Thread para receber mensagens de um peer."""
    global messages, blockchain, INFECTED, MALICIOUS_MODE
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

            if data.startswith("USERNAME:"):
                peer_username = data.split(":", 1)[1]
                peer_names[conn] = peer_username
                update_peers_list()
                print(f"[PEER] {peer_username} conectado de {addr}")
                continue

            if data == "BLOCKCHAIN_REQ":
                # Se o modo malicioso estiver ativo E já infectado, envia blockchain corrompida
                if INFECTED:
                    insert_message(chat_box,
                                 "😈 ENVIANDO BLOCKCHAIN CORROMPIDA! 😈",
                                 "system")
                    print("[MALICIOSO] Enviando blockchain adulterada para peer")

                # Peer pediu a blockchain (silencioso - não loga)
                chain_data = json.dumps(blockchain.to_list())
                conn.sendall(f"BLOCKCHAIN_RESP\n{chain_data}".encode("utf-8"))
                continue

            if data.startswith("BLOCKCHAIN_RESP"):
                # Se estiver infectado, NÃO aceita blockchain de outros peers
                if INFECTED:
                    insert_message(chat_box,
                                 "🦠 ISOLADO: Blockchain local está corrompida, rejeitando sincronização!",
                                 "system")
                    print("[INFECTADO] Rejeitando blockchain de peer legítimo - estamos corrompidos")
                    continue

                try:
                    _, chain_json = data.split("\n", 1)
                    other_chain = json.loads(chain_json)

                    # Tenta mesclar
                    if blockchain.merge(other_chain):
                        print("[BLOCKCHAIN] Chain atualizada de outro peer")
                        messages.clear()
                        for block in blockchain.chain[1:]:
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
                history = "\n".join(messages)
                conn.sendall(f"HISTORY_RESP\n{history}".encode("utf-8"))
                continue

            if data.startswith("HISTORY_RESP"):
                _, history = data.split("\n", 1)
                for msg in history.split("\n"):
                    if msg and msg not in messages:
                        messages.append(msg)
                        insert_message(chat_box, msg, "received")
                continue

            # Recebe BLOCO com validação criptográfica
            if data.startswith("BLOCK:"):
                print(f"[DEBUG] INFECTED={INFECTED}, blockchain.is_valid()={blockchain.is_valid()}")

                # Se infectado, bloqueia TODOS os blocos
                if INFECTED:
                    insert_message(chat_box,
                                 "🦠 BLOQUEADO: Bloco rejeitado (peer infectado)",
                                 "system")
                    print(f"[INFECTADO] Bloco bloqueado - peer está isolado")
                    continue

                # VALIDAÇÃO 0: Nossa blockchain está íntegra?
                if not blockchain.is_valid():
                    insert_message(chat_box,
                                 "⚠️ BLOCKCHAIN LOCAL CORROMPIDA! Auto-isolando...",
                                 "system")
                    print("[SEGURANÇA] Blockchain local inválida! Auto-isolamento ativado.")
                    INFECTED = True
                    MALICIOUS_MODE = True
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
                print(f"[DEBUG] INFECTED={INFECTED}, blockchain.is_valid()={blockchain.is_valid()}")

                if INFECTED:
                    insert_message(chat_box,
                                 f"🦠 BLOQUEADO: {data}",
                                 "system")
                    print(f"[INFECTADO] Mensagem bloqueada - peer está isolado: {data}")
                    continue

                if not blockchain.is_valid():
                    insert_message(chat_box,
                                 "⚠️ BLOCKCHAIN CORROMPIDA! Rejeitando novas mensagens.",
                                 "system")
                    print("[SEGURANÇA] Blockchain inválida! Rejeitando mensagem.")
                    INFECTED = True
                    MALICIOUS_MODE = True
                    continue

                messages.append(data)
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
        update_peers_list()


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
        known_peers.add(addr)
        
        try:
            conn.sendall(f"USERNAME:{username}".encode("utf-8"))
        except:
            pass
        
        update_peers_list()
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
        known_peers.add((ip, port))
        
        try:
            conn.sendall(f"USERNAME:{username}".encode("utf-8"))
            time.sleep(0.1)
        except:
            pass
        
        update_peers_list()
        
        threading.Thread(
            target=handle_peer, args=(conn, (ip, port), chat_box), daemon=True
        ).start()

        time.sleep(0.1)
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
    title = "Blockchain Info - INFECTADO ⚠️" if INFECTED else "Blockchain Info"
    info_window.title(title)
    info_window.geometry("500x400")

    text = scrolledtext.ScrolledText(info_window, wrap=tk.WORD, width=60, height=20)
    text.pack(padx=10, pady=10)

    # Informações da blockchain
    header = "═══ BLOCKCHAIN INFO (INFECTADA) ═══\n\n" if INFECTED else "═══ BLOCKCHAIN INFO ═══\n\n"
    text.insert(tk.END, header)
    text.insert(tk.END, f"Total de blocos: {len(blockchain.chain)}\n")

    is_valid = blockchain.is_valid()
    status = '✓ SIM' if is_valid else '✗ NÃO (ADULTERADA!)'
    text.insert(tk.END, f"Blockchain válida: {status}\n\n")

    if not is_valid:
        text.insert(tk.END, "⚠️ ATENÇÃO: Esta blockchain foi ADULTERADA!\n")
        text.insert(tk.END, "⚠️ Outros peers REJEITARÃO esta chain!\n\n")

    text.insert(tk.END, "═══ BLOCOS ═══\n\n")

    for block in blockchain.chain:
        text.insert(tk.END, f"Bloco #{block.index}\n")
        text.insert(tk.END, f"  Hash: {block.hash[:16]}...\n")
        text.insert(tk.END, f"  Hash Anterior: {block.previous_hash[:16]}...\n")
        text.insert(tk.END, f"  Dados: {block.data[:50]}...\n" if len(block.data) > 50 else f"  Dados: {block.data}\n")

        # Verifica se o bloco está corrompido
        if block.hash != block.calculate_hash():
            text.insert(tk.END, "  ⚠️ BLOCO ADULTERADO!\n")

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
    root.withdraw()

    username = simpledialog.askstring("Usuário",
                                     "Digite seu nome:",
                                     parent=root)
    if not username:
        username = "Usuario"

    root.deiconify()

    # Referências globais para atualizar a UI
    ui_elements = {}

    def update_ui_theme():
        """Atualiza o tema da interface baseado no estado de infecção."""
        if INFECTED:
            root.title(f"😈 P2P Chat - {username} [INFECTADO] ⚠️")
            root.configure(bg="#330000")
            ui_elements['main_frame'].configure(bg="#330000")
            ui_elements['left_frame'].configure(bg="#330000")
            ui_elements['right_frame'].configure(bg="#330000")
            ui_elements['peers_label'].configure(text="😈 Peers", bg="#330000", fg="red")
            ui_elements['peers_listbox'].configure(bg="#1a0000", fg="red")
            ui_elements['warning_label'].configure(text="⚠️ BLOCKCHAIN INFECTADA - PEER ISOLADO DA REDE ⚠️",
                                                   bg="red", fg="white")
            ui_elements['warning_label'].pack(fill=tk.X, pady=(0, 5))
            ui_elements['chat_box'].configure(bg="#1a0000", fg="red")
            ui_elements['entry'].configure(bg="#1a0000", fg="red")
            ui_elements['send_btn'].configure(bg="#660000", fg="white")
            ui_elements['blockchain_btn'].configure(bg="#660000", fg="white")
            ui_elements['infect_btn'].configure(bg="#660000", fg="gray", state="disabled",
                                               text="🦠 Infectado")
            ui_elements['bottom_frame'].configure(bg="#330000")
        else:
            root.title(f"P2P Chat - {username}")
            root.configure(bg="#2b2b2b")
            ui_elements['main_frame'].configure(bg="#2b2b2b")
            ui_elements['left_frame'].configure(bg="#2b2b2b")
            ui_elements['right_frame'].configure(bg="#2b2b2b")
            ui_elements['peers_label'].configure(text="👥 Peers", bg="#2b2b2b", fg="white")
            ui_elements['peers_listbox'].configure(bg="#1e1e1e", fg="white")
            ui_elements['warning_label'].pack_forget()
            ui_elements['chat_box'].configure(bg="#1e1e1e", fg="white")
            ui_elements['entry'].configure(bg="#1e1e1e", fg="white")
            ui_elements['send_btn'].configure(bg="#4a4a4a", fg="white")
            ui_elements['blockchain_btn'].configure(bg="#4a4a4a", fg="white")
            ui_elements['infect_btn'].configure(bg="red", fg="white", state="normal")
            ui_elements['bottom_frame'].configure(bg="#2b2b2b")

        update_peers_list()

    root.geometry("800x500")
    root.configure(bg="#2b2b2b")

    # Frame principal
    main_frame = tk.Frame(root, bg="#2b2b2b")
    main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    ui_elements['main_frame'] = main_frame

    # Painel esquerdo
    left_frame = tk.Frame(main_frame, width=200, bg="#2b2b2b")
    left_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 5))
    ui_elements['left_frame'] = left_frame

    peers_label = tk.Label(left_frame, text="👥 Peers",
                          font=("Arial", 10, "bold"),
                          bg="#2b2b2b", fg="white")
    peers_label.pack(pady=(0, 5))
    ui_elements['peers_label'] = peers_label

    peers_listbox = tk.Listbox(left_frame, width=25, height=20,
                               font=("Courier", 9),
                               bg="#1e1e1e", fg="white")
    peers_listbox.pack(fill=tk.BOTH, expand=True)
    ui_elements['peers_listbox'] = peers_listbox

    # Painel direito
    right_frame = tk.Frame(main_frame, bg="#2b2b2b")
    right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    ui_elements['right_frame'] = right_frame

    # Aviso no topo (inicialmente oculto)
    warning_label = tk.Label(right_frame,
                            text="⚠️ BLOCKCHAIN INFECTADA - MODO MALICIOSO ATIVO ⚠️",
                            bg="red", fg="white", font=("Arial", 10, "bold"))
    ui_elements['warning_label'] = warning_label

    chat_box = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD,
                                        width=50, height=20, state="disabled",
                                        bg="#1e1e1e", fg="white")
    chat_box.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
    ui_elements['chat_box'] = chat_box

    # Estilos - atualizar para modo normal
    chat_box.tag_config("left", justify="left", foreground="#4a9eff")
    chat_box.tag_config("right", justify="right", foreground="#4caf50")
    chat_box.tag_config("center", justify="center", foreground="gray",
                       font=("Arial", 9, "bold"))

    # Frame inferior
    bottom_frame = tk.Frame(right_frame, bg="#2b2b2b")
    bottom_frame.pack(fill=tk.X)
    ui_elements['bottom_frame'] = bottom_frame

    entry = tk.Entry(bottom_frame, width=40, bg="#1e1e1e", fg="white")
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    ui_elements['entry'] = entry

    def send_msg(event=None):
        msg = entry.get().strip()
        if msg:
            # VALIDAÇÃO AUTOMÁTICA: Verifica se a blockchain está íntegra
            if not blockchain.is_valid():
                global INFECTED, MALICIOUS_MODE
                INFECTED = True
                MALICIOUS_MODE = True

                insert_message(chat_box,
                             "🦠 BLOQUEADO: Blockchain LOCAL corrompida detectada!",
                             "system")
                insert_message(chat_box,
                             "⚠️ Adulteração detectada - peer auto-isolado.",
                             "system")
                insert_message(chat_box,
                             "⚠️ Sincronize com peers legítimos para restaurar.",
                             "system")
                print("[AUTO-DETECÇÃO] Blockchain inválida - bloqueando envio")

                # Atualiza interface para modo infectado
                update_ui_theme()

                entry.delete(0, tk.END)
                return

            full_msg = f"[{username}]: {msg}"
            messages.append(full_msg)
            new_block = blockchain.add_block(full_msg)
            print(f"[BLOCKCHAIN] Bloco #{len(blockchain.chain)-1} criado")

            insert_message(chat_box, full_msg, "sent")

            # Envia o BLOCO completo ao invés da mensagem pura
            block_data = json.dumps(new_block.to_dict())
            broadcast(f"BLOCK:{block_data}")

            entry.delete(0, tk.END)

    def infect_blockchain():
        """Chama a função de infecção e atualiza a UI."""
        if adulterate_blockchain_interactive(chat_box):
            update_ui_theme()
            insert_message(chat_box,
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                         "system")
            insert_message(chat_box,
                         "🦠 BLOCKCHAIN INFECTADA E CORROMPIDA! 🦠",
                         "system")
            insert_message(chat_box,
                         "⚠️ PEER COMPLETAMENTE ISOLADO DA REDE!",
                         "system")
            insert_message(chat_box,
                         "⚠️ Você NÃO pode mais enviar mensagens!",
                         "system")
            insert_message(chat_box,
                         "⚠️ Você NÃO receberá mais mensagens!",
                         "system")
            insert_message(chat_box,
                         "⚠️ Todos os blocos enviados serão REJEITADOS!",
                         "system")
            insert_message(chat_box,
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                         "system")

    send_btn = tk.Button(bottom_frame, text="Enviar", command=send_msg,
                        bg="#4a4a4a", fg="white")
    send_btn.pack(side=tk.LEFT, padx=5)
    ui_elements['send_btn'] = send_btn

    blockchain_btn = tk.Button(bottom_frame, text="📊 Blockchain",
                              command=show_blockchain_info,
                              bg="#4a4a4a", fg="white")
    blockchain_btn.pack(side=tk.LEFT, padx=5)
    ui_elements['blockchain_btn'] = blockchain_btn

    infect_btn = tk.Button(bottom_frame, text="🦠 Infectar",
                          command=infect_blockchain,
                          bg="red", fg="white",
                          font=("Arial", 9, "bold"))
    infect_btn.pack(side=tk.LEFT, padx=5)
    ui_elements['infect_btn'] = infect_btn

    entry.bind("<Return>", send_msg)

    # Mensagem inicial
    insert_message(chat_box,
                  "✓ Peer P2P iniciado com sucesso",
                  "system")
    insert_message(chat_box,
                  "Aguardando conexões de outros peers...",
                  "system")

    update_peers_list()

    # Threads
    threading.Thread(target=start_server, args=(chat_box,), daemon=True).start()
    threading.Thread(target=multicast_announcer, args=(PORT,), daemon=True).start()
    threading.Thread(
        target=multicast_listener,
        args=(lambda ip, port: on_peer_discovered(ip, port, chat_box),),
        daemon=True
    ).start()

    root.mainloop()


if __name__ == "__main__":
    print("\n" + "="*60)
    print("🦠  PEER COM CAPACIDADE DE INFECÇÃO - MODO DEMONSTRAÇÃO  🦠")
    print("="*60)
    print("Este peer inicia NORMALMENTE, mas pode INFECTAR sua blockchain.")
    print("Clique no botão '🦠 Infectar' para adulterar a blockchain LOCAL.")
    print("Use APENAS para fins educacionais!")
    print("="*60 + "\n")

    start_gui()
