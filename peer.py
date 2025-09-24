import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog
from multicast import multicast_announcer, multicast_listener

PORT = 5555
messages = []        # histórico local
peers = {}           # {conn: (ip, port)}
username = None      # nome do usuário local


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
    global messages
    try:
        while True:
            data = conn.recv(4096).decode("utf-8")
            if not data:
                break

            if data == "HISTORY_REQ":
                # Novo peer pediu histórico
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
                insert_message(chat_box, data, "received")
                broadcast(data, origin=conn)
    except:
        pass
    finally:
        conn.close()
        peers.pop(conn, None)


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
        threading.Thread(
            target=handle_peer, args=(conn, addr, chat_box), daemon=True
        ).start()


def connect_to_peer(ip, port, chat_box):
    """Conecta em um peer existente e pede histórico."""
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((ip, port))
        peers[conn] = (ip, port)
        threading.Thread(
            target=handle_peer, args=(conn, (ip, port), chat_box), daemon=True
        ).start()

        # pede histórico
        conn.sendall("HISTORY_REQ".encode("utf-8"))
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


def start_gui():
    global username
    root = tk.Tk()
    root.withdraw()  # esconde janela enquanto pergunta nome

    username = simpledialog.askstring("Usuário", "Digite seu nome de usuário:", parent=root)
    if not username:
        username = "Anônimo"

    root.deiconify()
    root.title(f"P2P Chat - {username}")

    chat_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20, state="disabled")
    chat_box.pack(padx=10, pady=10)

    # estilos
    chat_box.tag_config("left", justify="left", foreground="blue")
    chat_box.tag_config("right", justify="right", foreground="green")
    chat_box.tag_config("center", justify="center", foreground="gray", font=("Arial", 8, "italic"))

    entry = tk.Entry(root, width=40)
    entry.pack(side=tk.LEFT, padx=10, pady=10)

    def send_msg(event=None):
        msg = entry.get().strip()
        if msg:
            full_msg = f"[{username}]: {msg}"
            messages.append(full_msg)
            insert_message(chat_box, full_msg, "sent")
            broadcast(full_msg)
            entry.delete(0, tk.END)

    send_btn = tk.Button(root, text="Enviar", command=send_msg)
    send_btn.pack(side=tk.LEFT, padx=5)

    entry.bind("<Return>", send_msg)

    # Inicia threads de rede
    threading.Thread(target=start_server, args=(chat_box,), daemon=True).start()
    threading.Thread(target=multicast_announcer, args=(PORT,), daemon=True).start()
    threading.Thread(
        target=multicast_listener, args=(lambda ip, port: connect_to_peer(ip, port, chat_box),), daemon=True
    ).start()

    root.mainloop()


if __name__ == "__main__":
    start_gui()
