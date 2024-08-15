import models
import re
import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import CAST
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES3

import secrets
from cryptography.hazmat.backends import default_backend

users = []
private_key_rings = []
public_key_rings = []
logged_user = None

def register_action(username, email, password, set_status):
    global logged_user
    print("Register button clicked")
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if logged_user is not None:
        set_status("User must be logged out.")
    elif username == "" or email == "" or password == "":
        set_status("All fields are mandatory. ")
    elif not re.match(email_pattern, email):
        set_status("Not valid format for email. ")
    else:
        found = False
        # check if user with this username already exists
        for user in users:
            if user.username == username:
                found = True
                break

        if found:
            set_status("User already exists. ")
        else: # if not, we create a new user
            user = models.User(username, email, password)
            logged_user = user
            users.append(logged_user)
            logged_user.print_user()

            #creating directories

            current_directory = os.path.dirname(os.path.abspath(__file__))

            user_directory = os.path.join(current_directory, username)

            send_directory = os.path.join(user_directory, 'send')
            receive_directory = os.path.join(user_directory, 'receive')
            export_directory = os.path.join(user_directory, 'export')

            os.makedirs(send_directory, exist_ok=True)
            os.makedirs(receive_directory, exist_ok=True)
            os.makedirs(export_directory, exist_ok=True)

            #adding user to private key rings

            private_key_rings.append(models.PrivateKeyRing(email))

            set_status("Success")

def login_action(username, password, set_status):
    global logged_user
    print("Login button clicked")
    if logged_user is not None:
        set_status("User must be logged out. ")
    elif username == "" or password == "":
        set_status("All fields are mandatory. ")
    else:
        found = False

        for user in users:
            if user.username == username and user.check_password(password):
                found = True
                logged_user = user
                set_status("You successfully logged in. ")
                logged_user.print_user()

        if not found:
            set_status("User not found. Try again. ")

def generate_key_pair_action(key_size, set_status):
    global logged_user
    print("Generate key pair button clicked")
    if logged_user is None:
        set_status("User must be logged in. ")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        logged_user.add_key_pair(private_key, public_key)

        #logged_user.print_user()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        for key in private_key_rings:
            if key.user_id == logged_user.email:
                # Serijalizacija javnog ključa u PEM ili DER format (izaberite DER za bajtove)
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                # Kreiranje key id
                # Konvertovanje bajtova u integer (bajtova niz u broj)
                public_key_int = int.from_bytes(public_key_bytes, byteorder='big')
                # Izdvajanje poslednjih 64 bita
                key_id = public_key_int & ((1 << 64) - 1)

                # Kreiranje SHA-1 objekta
                digest = hashes.Hash(hashes.SHA1())

                # Dodavanje podataka koje želite da heširate
                digest.update(logged_user.password)

                # Dobijanje heš vrednosti
                hash_value = digest.finalize()

                cast_key = hash_value[:16]  # CAST-128 ključ mora biti između 5 i 16 bajtova

                # Generisanje vektora inicijalizacije (IV)
                iv = get_random_bytes(8)  # CAST-128 koristi 8-bajtni IV

                # Kreiranje CAST-128 objekta za šifrovanje
                cipher = CAST.new(cast_key, CAST.MODE_CBC, iv)

                # Serijalizacija privatnog ključa u bajtove (PEM format bez enkripcije)
                private_key_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )

                # Padding podataka (CAST-128 koristi blokove od 8 bajtova)
                padded_data = pad(private_key_bytes, CAST.block_size)

                # Korak 3: Šifrovanje privatnog ključa
                encrypted_private_key = cipher.encrypt(padded_data)

                key.add_key(time.time(), key_id, public_key, encrypted_private_key)

                set_status("Success generating keys. ")

                key.print_ring()

        #print(private_pem, public_pem)

def get_private_key_ring(set_status):
    global logged_user

    if logged_user is None:
        set_status("User must be logged in. ")

    else:
        for private_key_ring in private_key_rings:
            if private_key_ring.get_user_id() == logged_user.get_email():
                return private_key_ring
    return None

def get_public_key_ring(set_status):
    global logged_user

    if logged_user is None:
        set_status("User must be logged in. ")
    else:
        for public_key_ring in public_key_rings:
            if public_key_ring.user == logged_user.email:
                return public_key_ring
    return None

def send_message_action(filename, filepath, encryption_var, signature_var, compress_var, radix64_var, encryption_option, signature_option, enc_input, signature_input, message, set_status):
    global logged_user

    if logged_user is None:
        set_status("User must be logged in. ")
    elif filename.get() is None and filepath.get() is None:
        set_status("Fields with * are mandatory. ")
    else:
        if encryption_var.get():
            if enc_input.get() is None:
                set_status("Please input user id for encryption. ")
            else:
                user_id = enc_input.get()
                email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

                if not re.match(email_pattern, user_id):
                    set_status("Invalid format for user id. ")
                else:
                    for user in users:
                        print(user.email)
                        print(user_id)
                        if user.email == user_id:
                            # treba da proverimo da li ima generisan par kljuceva uopste
                            if len(user.my_keys) == 0:
                                set_status("Can't send the message. ")
                            else:
                                # ako ima generisemo random sesijski kljuc
                                session_key = secrets.token_bytes(16)
                                # sesijskim kljucem kriptujemo poruku

                                if encryption_option.get() == 1:
                                    print("TripleDES")

                                    print(message.get("1.0", "end-1c"))

                                    message_bytes = message.get("1.0", "end-1c").encode('utf-8')

                                    cipher = DES3.new(session_key, DES3.MODE_CBC)

                                    # Encrypt the data
                                    iv = cipher.iv  # Initialization Vector (IV)
                                    ciphertext = cipher.encrypt(pad(message_bytes, DES3.block_size))

                                    print(f'Ciphertext: {ciphertext.hex()}')

                                    print(session_key)

                                    # sesijski kljuc kriptujemo pomocu rsa koristeci javni kljuc od primaoca, dodamo kljuc poruci
                                    session_key_ciphertxt = user.my_keys[0]["public_key"].encrypt(
                                        session_key,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    )

                                    print(f"Ciphertext Ks: {session_key_ciphertxt.hex()}")

                                    # treba da dodamo nas javni kljuc u njihov public key ring
                                    for public_key_ring in public_key_rings:
                                        if public_key_ring.user == user.email:
                                            public_key_bytes = user.my_keys[0]["public_key"].public_bytes(
                                                encoding=serialization.Encoding.DER,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                            )

                                            # Kreiranje key id
                                            # Konvertovanje bajtova u integer (bajtova niz u broj)
                                            public_key_int = int.from_bytes(public_key_bytes, byteorder='big')
                                            # Izdvajanje poslednjih 64 bita
                                            key_id = public_key_int & ((1 << 64) - 1)

                                            public_key_ring.add_key(logged_user.email, time.time(), key_id, user.my_keys[0]["public_key"])

                                            public_key_ring.print_ring()

                                            break


                                    # DEKRIPCIJA

                                    # session_key_plaintext = user.my_keys[0]["private_key"].decrypt(
                                    #     ciphertext,
                                    #     padding.OAEP(
                                    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    #         algorithm=hashes.SHA256(),
                                    #         label=None
                                    #     )
                                    # )
                                    #
                                    # print(f"Decrypted message: {session_key_plaintext.decode()}")

                                    # Decrypt the data
                                    cipher_decrypt = DES3.new(session_key, DES3.MODE_CBC, iv=iv)
                                    plaintext = unpad(cipher_decrypt.decrypt(ciphertext), DES3.block_size)

                                    print(f'Plaintext: {plaintext.decode()}')
                                elif encryption_option.get() == 2:
                                    print("CAST5")

                            break
                        else:
                            set_status("User not found. ")



def receive_msg_action():
    print("Receive message button clicked")

def import_keys_action():
    print("Import keys button clicked")

def export_keys_action():
    print("Export keys button clicked")

def log_out_action():
    global logged_user
    print("Log out button clicked")
    logged_user = None

if __name__ == '__main__':
    print("Can't run this file. Try main.py")