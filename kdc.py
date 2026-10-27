import socket
import threading
import secrets
import string
import aes

PORT = 5000
k_a = ""
k_b = ""


def ask_key(label):
    while True:
        key = input(f"Enter {label} (16 ASCII characters): ")
        if aes.check_key(key): return key
        print("Error: key must contain exactly 16 ASCII characters.")

def send(file, message):
    file.write(message + "\n")
    file.flush()

def new_session_key():
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(16))

def serve(conn):
    with conn:
        with conn.makefile("rw") as file:
            request = file.readline().strip()

            if not request: return
            parts = request.split("|")
            if len(parts) != 4:
                print("Invalid request format.")
                return

            id_a, id_b, n_1, mode = parts
            mode = mode.upper()

            if id_a != "alice" or id_b != "bob":
                print("Unknown users. Request rejected.")
                return

            if mode not in ("CTR", "ECB"):
                print("Invalid encryption mode.")
                return

            session_key = new_session_key()

            ticket_plaintext = f"{session_key}|{id_a}|{mode}"
            ticket = aes.encrypt(k_b, ticket_plaintext, mode)

            response_plaintext = (f"{session_key}|{id_b}|{n_1}|{ticket}")
            response = aes.encrypt(k_a, response_plaintext, mode)
            send(file, response)

def listen():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen()

    print(f"\nKDC listening on port {PORT}.")

    while True:
        conn, address = server.accept()
        print(f"\nConnection from: {address[0]}")

        threading.Thread(
            target=handle_connection,
            args=(conn,),
            daemon=True
        ).start()


def handle_connection(conn):
    try:
        serve(conn)
    except Exception as error:
        print(f"KDC request failed: {error}")
        conn.close()


def main():
    global k_a, k_b

    k_a = ask_key("Alice's master key (k_a)")
    k_b = ask_key("Bob's master key (k_b)")

    threading.Thread(target=listen, daemon=True).start()

    while True:
        print("\n===== KDC MENU =====")
        print("1. Change Alice's key (k_a)")
        print("2. Change Bob's key (k_b)")
        print("3. Show settings")
        print("4. Exit")

        choice = input("Select option: ").strip()

        if choice == "1": k_a = ask_key("Alice's master key (k_a)")
        elif choice == "2": k_b = ask_key("Bob's master key (k_b)")
        elif choice == "3":
            print(f"Alice's key: {k_a}")
            print(f"Bob's key: {k_b}")
        elif choice == "4":
            print("Exiting KDC.")
            break
        else: print("Invalid option.")

if __name__ == "__main__":
    main()