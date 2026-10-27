import socket
import threading
import aes

KDC_PORT = 5000
BOB_PORT = 6000
ID_A = "alice"
ID_B = "bob"


def ask_key(label):
    while True:
        key = input(f"Enter {label} (16 ASCII characters): ")
        if aes.check_key(key): return key
        print("Error: key must contain exactly 16 ASCII characters.")

def ask_mode():
    while True:
        print("\n===== ENCRYPTION MODE =====")
        print("1. AES-CTR")
        print("2. AES-ECB")

        choice = input("Select mode: ").strip()
        if choice == "1": return "CTR"
        if choice == "2":return "ECB"

        print("Invalid option.")

def send(file, message):
    file.write(message + "\n")
    file.flush()

def ask_kdc(k_a, kdc_ip, mode):
    n_1 = aes.random_number()

    with socket.create_connection((kdc_ip, KDC_PORT)) as conn:
        with conn.makefile("rw") as file:
            request = f"{ID_A}|{ID_B}|{n_1}|{mode}"
            send(file, request)
            reply = file.readline().strip()
    if not reply:
        raise ConnectionError("KDC returned an empty response.")

    plaintext = aes.decrypt(k_a, reply)
    parts = plaintext.split("|", 3)

    if len(parts) != 4: raise ValueError("Invalid KDC response format.")
    session_key, id_b, n_1_back, ticket = parts
    if id_b != ID_B or int(n_1_back) != n_1: raise ValueError("KDC response verification failed.")

    print("Session key received from KDC.")
    print("KDC response verified.")

    return session_key, ticket


def receive_messages(file, session_key, done):
    try:
        for line in file:
            message = line.strip()
            if not message: continue
            try:
                plaintext = aes.decrypt(session_key, message)
                print(f"\nBob ciphertext: {message}")
                print(f"Bob's message: {plaintext}")
            except (ValueError, UnicodeError):
                print("\nCould not decrypt Bob's message.")
    except OSError:
        pass
    finally:
        done.set()
        print("\nBob disconnected. Press Enter to return.")

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
            text = input("alice> ")
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

def start_session(k_a, kdc_ip, bob_ip, mode):
    session_key, ticket = ask_kdc(k_a, kdc_ip, mode)

    print(f"\nConnecting to Bob using AES-{mode}...")

    conn = socket.create_connection((bob_ip, BOB_PORT))
    file = conn.makefile("rw")

    try:
        send(file, ticket)
        challenge = file.readline().strip()
        if not challenge: raise ConnectionError("Bob did not send a challenge.")
        n_2 = int(aes.decrypt(session_key, challenge))

        answer = aes.encrypt(session_key, str(n_2 - 1), mode)
        send(file, answer)

        status = file.readline().strip()
        if status != "ok": raise ValueError("Bob rejected the handshake.")

        print("Handshake successful.")
        print(f"Communication mode: {mode}")
        chat(conn, file, session_key, mode)

    except Exception:
        conn.close()
        raise

def main():
    k_a = ask_key("Alice's master key (k_a)")
    kdc_ip = input("KDC IP address: ").strip()
    bob_ip = input("Bob IP address: ").strip()

    while True:
        print("\n===== ALICE MENU =====")
        print("1. Start chat using AES-CTR")
        print("2. Start chat using AES-ECB")
        print("3. Change master key (k_a)")
        print("4. Change server IP addresses")
        print("5. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":
            try:
                start_session(k_a, kdc_ip, bob_ip, "CTR")
            except Exception as error:
                print(f"Connection failed: {error}")

        elif choice == "2":
            try:
                start_session(k_a, kdc_ip, bob_ip, "ECB")
            except Exception as error:
                print(f"Connection failed: {error}")

        elif choice == "3":
            k_a = ask_key("Alice's master key (k_a)")

        elif choice == "4":
            kdc_ip = input("KDC IP address: ").strip()
            bob_ip = input("Bob IP address: ").strip()

        elif choice == "5":
            print("Exiting Alice.")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()