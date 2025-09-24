import socket
import struct
import time
import threading

MULTICAST_GROUP = "224.1.1.1"
MULTICAST_PORT = 5007
MULTICAST_TTL = 2


def multicast_announcer(local_port=5555):
    """Envia periodicamente a porta deste peer via multicast."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)

    msg = str(local_port).encode("utf-8")
    while True:
        sock.sendto(msg, (MULTICAST_GROUP, MULTICAST_PORT))
        time.sleep(2)


def multicast_listener(on_peer_found):
    """Escuta anúncios multicast e informa peers encontrados."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", MULTICAST_PORT))

    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        data, addr = sock.recvfrom(1024)
        peer_port = int(data.decode("utf-8"))
        peer_ip = addr[0]
        if on_peer_found:
            on_peer_found(peer_ip, peer_port)
