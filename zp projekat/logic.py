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

users = []
private_key_rings = []
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

def send_msg_action():
    print("Send message button clicked")

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