import socket
import threading
import aes

BOB_PORT = 6000
k_b = ""


def ask_key(label):
    while True:
        key = input(f"Enter {label} (16 ASCII characters): ")
        if aes.check_key(key): return key
        print("Error: key must contain exactly 16 ASCII characters.")

def send(file, message):
    file.write(message + "\n")
    file.flush()

def handshake(file):
    ticket = file.readline().strip()
    if not ticket: raise ConnectionError("Alice disconnected before sending the ticket.")

    ticket_plaintext = aes.decrypt(k_b, ticket)
    parts = ticket_plaintext.split("|")

    if len(parts) != 3: raise ValueError("Invalid ticket format.")

    session_key, id_a, mode = parts
    if id_a != "alice": raise ValueError("Invalid sender in ticket.")
    if mode not in ("CTR", "ECB"): raise ValueError("Invalid encryption mode in ticket.")

    print("Ticket accepted.")
    print(f"Session mode: AES-{mode}")

    n_2 = aes.random_number()
    challenge = aes.encrypt(session_key, str(n_2), mode)
    send(file, challenge)
    response = file.readline().strip()

    if not response: raise ConnectionError("Alice disconnected during handshake.")
    answer = int(aes.decrypt(session_key, response))

    if answer != n_2 - 1:
        send(file, "fail")
        raise ValueError("Alice failed the challenge.")

    send(file, "ok")
    print("Handshake successful.")
    print(f"Communication mode: {mode}")
    return session_key, mode

def receive_messages(file, session_key, done):
    try:
        for line in file:
            message = line.strip()
            if not message: continue
            try:
                plaintext = aes.decrypt(session_key, message)
                print(f"\nAlice ciphertext: {message}")
                print(f"Alice's message: {plaintext}")
            except (ValueError, UnicodeError):
                print("\nCould not decrypt Alice's message.")
    except OSError:
        pass
    finally:
        done.set()
        print("\nAlice disconnected. Press Enter to return.")

def chat(conn, file, session_key, mode):
    done = threading.Event()

    threading.Thread(
        target=receive_messages,
        args=(file, session_key, done),
        daemon=True
    ).start()

    print(f"\nChat started using AES-{mode}.")
    print("Type /exit to end the session.")

    while not done.is_set():
        try:
            text = input("bob> ")
        except (EOFError, KeyboardInterrupt):
            break

        if done.is_set() or text == "/exit": break

        try:
            ciphertext = aes.encrypt(session_key, text, mode)
            send(file, ciphertext)
            print(f"Plaintext : {text}")
            print(f"Ciphertext: {ciphertext}")
        except (ValueError, UnicodeError) as error:
            print(f"Encryption failed: {error}")
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    conn.close()


def main():
    global k_b
    k_b = ask_key("Bob's master key (k_b)")

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", BOB_PORT))
    server.listen()

    print(f"Bob server listening on port {BOB_PORT}.")

    while True:
        print("\n===== BOB MENU =====")
        print("1. Wait for Alice")
        print("2. Change master key (k_b)")
        print("3. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":
            print("Waiting for Alice...")
            conn, address = server.accept()
            print(f"Connection from: {address[0]}")
            file = conn.makefile("rw")

            try:
                session_key, mode = handshake(file)
                chat(conn, file, session_key, mode)
            except Exception as error:
                print(f"Session failed: {error}")
                conn.close()

        elif choice == "2": k_b = ask_key("Bob's master key (k_b)")
        elif choice == "3":
            server.close()
            print("Exiting Bob.")
            break
        else: print("Invalid option.")

if __name__ == "__main__":
    main()