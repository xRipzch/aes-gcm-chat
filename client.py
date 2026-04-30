import hashlib
import os
import socket
import sys
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# constant ( skal matche med serverens )
DEFAULT_HOST = "localhost"
SERVER_PORT = 12002
UDP_PORT = 12003    # UDP port til key exchange
KEY_SIZE = 32       # 256 bit aes nøgle
NOUNCE_SIZE = 12
MSG_LEN_HDR = 4

## Password verifikation


def hash_password(password: str) -> bytes:
    return hashlib.sha3_256(password.encode("utf-8")).digest()


## Encryption


def encrypt(key: bytes, plaintekst: str) -> bytes:
    aesgcm = AESGCM(key)
    nounce = os.urandom(NOUNCE_SIZE)
    ct = aesgcm.encrypt(nounce, plaintekst.encode("utf-8"), None)
    return nounce + ct


def decrypt(key: bytes, data: bytes) -> str:
    nounce = data[:NOUNCE_SIZE]
    ct = data[NOUNCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nounce, ct, None).decode("utf-8")


## Socket helpers


def send_frame(sock: socket.socket, data: bytes) -> None:
    header = len(data).to_bytes(MSG_LEN_HDR, "big")
    sock.sendall(header + data)


def recieve_frame(sock: socket.socket) -> bytes:
    raw_len = recieve_exactly(sock, MSG_LEN_HDR)
    if not raw_len:
        return b""
    lenght = int.from_bytes(raw_len, "big")
    return recieve_exactly(sock, lenght)


def recieve_exactly(sock: socket.socket, n: int) -> bytes:
    buff = b""
    while len(buff) < n:
        chunk = sock.recv(n - len(buff))
        if not chunk:
            return b""
        buff += chunk
    return buff


## Threading


def receive_loop(sock: socket.socket, key: bytes) -> None:
    while True:
        try:
            data = recieve_frame(sock)
            if not data:
                print("\n [Client] serveren disconnected.")
                os._exit(0)
            plaintekst = decrypt(key, data)
            print(f"\r[Server]: {plaintekst}\n[You]: ", end="", flush=True)
        except InvalidTag:
            print("\n ERROR: Decryption fejlde - forkert nøgle.")
            os._exit(1)
        except Exception as e:
            print(f"\n[Client] Receive fejl: {e}")
            os._exit(1)


## Main


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST

    print("_" * 65)
    print("Anvendt Kryptografi - Mandatory_02 | Anders Ravn | anra0002")
    print("_" * 65)

    # connect til server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, SERVER_PORT))
    except ConnectionRefusedError:
        print(f"[Error] Kunne ikke connecte til {host}:{SERVER_PORT}. Kører serveren?")
        sys.exit(1)
    print(f"[Network] Connected til {host}:{SERVER_PORT}")

    # generer AES nøglen og send den til serveren via UDP [én gang]
    key = os.urandom(KEY_SIZE)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.sendto(key, (host, UDP_PORT))
    udp_sock.close()
    print("[Crypto] AES-256 nøgle sendt til serveren via UDP.")

    # signal til serveren at klienten er klar + send password hash til verifikation
    password = input("[Setup] Indtast forud bestemt password: ")
    sock.sendall(b"\x01")
    sock.sendall(hash_password(password))

    print("[Crypto] Key exchange succesfuldt.")
    print("-" * 65)
    print("Chat connected - skriv besked, send med enter. | Ctrl+C til quit.")
    print("-" * 65)

    # background modtager thread
    recieve_tread = threading.Thread(
        target=receive_loop,
        args=(sock, key),
        daemon=True,  # dør automatisk når main lukkes
    )
    recieve_tread.start()

    # send main thread loop
    try:
        while True:
            msg = input("[You]: ")
            if not msg.strip():
                continue
            ciphertext = encrypt(key, msg)
            send_frame(sock, ciphertext)
    except KeyboardInterrupt:
        print("\n [Client] Disconnecting")
    except BrokenPipeError:
        print("\n [Client] Connection mistet")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
