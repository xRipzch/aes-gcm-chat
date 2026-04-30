import hashlib
import os
import socket
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constanter

SERVER_HOST = ""
SERVER_PORT = 12002   # skal matche clientet
UDP_PORT = 12003      # UDP port til key exchange
KEY_SIZE = 32         # 256bit aes nøgle
NONCE_SIZE = 12       # 96bit nonce til AES-GCM (NIST recommended)
MSG_LEN_HDR = 4       # længde prefix til framing
PASS_HASH_SIZE = 32   # SHA3-256 digest størrelse


# Password verifikation


def hash_password(password: str) -> bytes:
    return hashlib.sha3_256(password.encode("utf-8")).digest()


# Encryption helpers


def encrypt(key: bytes, plaintext: str) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct


def decrypt(key: bytes, data: bytes) -> str:
    nonce = data[:NONCE_SIZE]
    ct = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


# Socket helpers


def send_frame(sock: socket.socket, data: bytes) -> None:
    header = len(data).to_bytes(MSG_LEN_HDR, "big")
    sock.sendall(header + data)


def recieve_frame(sock: socket.socket) -> bytes:
    raw_len = recv_exactly(sock, MSG_LEN_HDR)
    if not raw_len:
        return b""
    length = int.from_bytes(raw_len, "big")
    return recv_exactly(sock, length)


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buff = b""
    while len(buff) < n:
        chunk = sock.recv(n - len(buff))
        if not chunk:
            return b""
        buff += chunk
    return buff


# Threading helper


def receive_loop(conn: socket.socket, key: bytes) -> None:
    while True:
        try:
            data = recieve_frame(conn)
            if not data:
                print("\n[Server] Client disconnectede.")
                os._exit(0)
            plaintext = decrypt(key, data)
            print(f"\r[Client]: {plaintext}\n[You]: ", end="", flush=True)
        except InvalidTag:
            print("\n [SERVER] Error: Dekryptering fejlede. Forkert nøgle!")
            os._exit(1)
        except Exception as e:
            print(f"[Server] Receive error: {e}")
            os._exit(1)


# main


def main() -> None:
    print("_" * 60)
    print("Anvendt Kryptografi - Mandatory_02 | Anders Ravn | anra0002")
    print("_" * 60)

    password = input("[Setup] Indtast forud bestemt password: ")
    own_hash = hash_password(password)

    # accpetere en tcp connection
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_HOST, SERVER_PORT))
    server_sock.listen(1)

    # lyt på UDP porten til key exchange
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((SERVER_HOST, UDP_PORT))

    print(f"[Network] Lytter på TCP port {SERVER_PORT} og UDP port {UDP_PORT} - venter på client")

    conn, addr = server_sock.accept()
    print(f"[Network] Client connected fra {addr[0]}:{addr[1]}")

    # modtag AES nøglen fra klienten via UDP [én gang]
    key, _ = udp_sock.recvfrom(KEY_SIZE)
    udp_sock.close()
    print("[Crypto] AES-256 nøgle modtaget via UDP.")

    # vent på at klienten har sendt sin nøgle og er klar
    ready = recv_exactly(conn, 1)
    if ready != b"\x01":
        print("[Error] Klienten svarede ikke korrekt på handshake.")
        conn.close()
        server_sock.close()
        return

    # verificer at klienten bruger det samme password
    client_hash = recv_exactly(conn, PASS_HASH_SIZE)
    if client_hash != own_hash:
        print("[Error] Forkert password - afviser klienten.")
        conn.close()
        server_sock.close()
        return

    print("[Crypto] Key exchange succesfuldt.")
    print("-" * 65)
    print("Chat connected - skriv besked, send med enter. | Ctrl+C til quit.")
    print("-" * 65)

    receive_thread = threading.Thread(
        target=receive_loop, args=(conn, key), daemon=True
    )
    receive_thread.start()

    try:
        while True:
            msg = input("[You]: ")
            if not msg.strip():
                continue
            ciphertext = encrypt(key, msg)
            send_frame(conn, ciphertext)
    except KeyboardInterrupt:
        print("\n [Server] lukker ned. ")
    except BrokenPipeError:
        print("\n [Server] Connection tabt")
    finally:
        conn.close()
        server_sock.close()


if __name__ == "__main__":
    main()
