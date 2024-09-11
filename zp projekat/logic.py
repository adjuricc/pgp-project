import base64
import zlib

import models
import json
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
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

import secrets
from cryptography.hazmat.backends import default_backend

users = []
private_key_rings = []
public_key_rings = []
logged_user = None
num_of_exports = []
ivs = []

tripledes_iv = None
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
            public_key_rings.append(models.PublicKeyRing(email))

            ivs.append(models.Ivs(email))

            num_of_exports.append({"username": username, "num": 0})

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
    global ivs

    print("Generate key pair button clicked")
    if logged_user is None:
        set_status("User must be logged in. ")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        print("PRIVATE KEY")
        print(private_key)

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

        # Dodavanje javnog kljuca u prsten javnih kljuceva

        for key in public_key_rings:
            if key.user_id == logged_user.email:
                key.add_key(logged_user.email, time.time(), key_id, public_key)
                break

        for key in private_key_rings:
            if key.user_id == logged_user.email:
                # Kreiranje SHA-1 objekta
                digest = hashes.Hash(hashes.SHA1())

                # Dodavanje podataka koje želite da heširate
                digest.update(logged_user.password)

                # Dobijanje heš vrednosti
                hash_value = digest.finalize()

                cast_key = hash_value[:16]  # CAST-128 ključ mora biti između 5 i 16 bajtova

                print("CAST KEY GENERATE")
                print(cast_key)

                # Generisanje vektora inicijalizacije (IV)
                iv = get_random_bytes(8)  # CAST-128 koristi 8-bajtni IV

                print("IV GENERATE")
                print(iv)

                for elem in ivs:
                    if elem.user_id == logged_user.email:
                        elem.add_value(iv)
                        break

                # Kreiranje CAST-128 objekta za šifrovanje
                cipher = CAST.new(cast_key, CAST.MODE_CBC, iv)

                # Serijalizacija privatnog ključa u bajtove (PEM format bez enkripcije)
                private_key_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )

                print("PRIVATE KEY GENERATE")
                print(private_key_bytes)

                # Padding podataka (CAST-128 koristi blokove od 8 bajtova)
                padded_data = pad(private_key_bytes, CAST.block_size)

                # Korak 3: Šifrovanje privatnog ključa
                encrypted_private_key = cipher.encrypt(padded_data)

                print("ENCRYPTED PRIVATE KEY GENERATE")
                print(encrypted_private_key)

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
            if private_key_ring.user_id == logged_user.email:
                return private_key_ring
    return None

def get_public_key_ring(set_status):
    global logged_user

    keys = []

    if logged_user is None:
        set_status("User must be logged in. ")
    else:
        for public_key_ring in public_key_rings:
            for key in public_key_ring.keys:
                keys.append(key)

        return keys
    return None

def send_message_action(filename, file_path, encryption_var, signature_var, compress_var, radix64_var, encryption_option, signature_option, enc_input, signature_input, message, set_status):
    global logged_user
    global ivs
    global tripledes_iv

    public_key_id = None
    signature = None

    if logged_user is None:
        set_status("User must be logged in. ")
    elif filename.get() is None or file_path.get() is None:
        set_status("Fields with * are mandatory. ")
    else:
        file_path_string = file_path.get() + "\\" + filename.get()
        # napravimo message koji se sastoji od filename, timestamp i data
        msg = {
            "filename": filename.get(),
            "timestamp": time.time(),
            "data": message.get("1.0", "end-1c")
        }

        # AUTENTIKACIJA
        if signature_var.get():
            # Kreiranje SHA-1 objekta
            digest = hashes.Hash(hashes.SHA1())

            # Dodavanje podataka koje želite da heširate
            message_bytes = (json.dumps(msg)).encode('utf-8')
            print("Message bytes send")
            print(message_bytes)
            print("Length send")
            print(len(message_bytes))
            digest.update(message_bytes)

            # Dobijanje heš vrednosti
            hashed_message = digest.finalize()
            print("Send")
            print(hashed_message)

            #DEKRIPTOVANJE PRIVATNOG KLJUCA

            key_index = int(signature_input.split(" ")[2])
            print(key_index)

            # Kreiranje SHA-1 objekta
            digest = hashes.Hash(hashes.SHA1())

            # Dodavanje podataka koje želite da heširate
            digest.update(logged_user.password)

            # Dobijanje heš vrednosti
            hash_value = digest.finalize()

            cast_key = hash_value[:16]  # CAST-128 ključ mora biti između 5 i 16 bajtova

            print("CAST KEY SEND")
            print(cast_key)

            # Generisanje vektora inicijalizacije (IV)
            iv = None

            for elem in ivs:
                if elem.user_id == logged_user.email:
                    iv = elem.values[key_index]
                    print("IV SEND")
                    print(iv)
                    break

            # Kreiranje CAST-128 objekta za dešifrovanje
            cipher = CAST.new(cast_key, CAST.MODE_CBC, iv)

            private_key_input = None
            key_id_sender = None

            for key in private_key_rings:
                if key.user_id == logged_user.email:
                    private_key_input = key.user_keys[key_index]["private_key"]
                    key_id_sender = key.user_keys[key_index]["key_id"]
                    break

            print("ENCRYPTED PRIVATE KEY SEND")
            print(private_key_input)

            decrypted_private_key_padded = cipher.decrypt(private_key_input)

            # Korak 3: Uklanjanje padding-a
            decrypted_private_key = unpad(decrypted_private_key_padded, CAST.block_size)

            # Korak 4: Deserijalizacija privatnog ključa
            private_key = serialization.load_pem_private_key(
                decrypted_private_key,
                password=None
            )

            decrypted_private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            print("PRIVATE KEY SEND")
            print(decrypted_private_key_bytes)


            print("SEND PRIVATE KEY")
            print(private_key)

            signature = private_key.sign(
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            found = False

            for ring in private_key_rings:
                if ring.user_id == logged_user.email:
                    for elem in ring.user_keys:
                        if elem["private_key"] == private_key_input:
                            public_key_id = elem["key_id"]
                            found = True
                            break
                    if found:
                        break

        message_bytes = (json.dumps(msg)).encode('utf-8')

        if encryption_var.get():
            if enc_input.get() is None:
                set_status("Please input user id for encryption. ")
            else:
                # nadji user_id preko public key
                public_key_input = enc_input.get()

                user_id = None

                print(private_key_rings)

                for private_key_ring in private_key_rings:
                    for key in private_key_ring.user_keys:
                        if key["key_id"] == int(public_key_input):
                            user_id = private_key_ring.get_user_id()
                            break

                if user_id is None:
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

                                # sesijski kljuc kriptujemo pomocu rsa koristeci javni kljuc od primaoca, dodamo kljuc poruci
                                session_key_ciphertxt = user.my_keys[0]["public_key"].encrypt(
                                    session_key,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )

                                recipient_public_key_bytes = user.my_keys[0]["public_key"].public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                recipient_public_key_int = int.from_bytes(recipient_public_key_bytes, byteorder='big')

                                recipient_key_id = recipient_public_key_int & ((1 << 64) - 1)

                                #message_bytes = (json.dumps(msg)).encode('utf-8')

                                if signature_var.get():
                                    signature_message = {"message": msg, "signature": signature}

                                # triple des alg
                                if encryption_option.get() == 1:
                                    print("TripleDES")

                                    cipher = DES3.new(session_key, DES3.MODE_CBC)

                                    iv = cipher.iv  # Initialization Vector (IV)
                                    tripledes_iv = iv
                                    if signature_var.get():
                                        signature_message_bytes = (json.dumps(signature_message)).encode('utf-8')
                                        ciphertext = cipher.encrypt(pad(signature_message_bytes, DES3.block_size))
                                    else:
                                        ciphertext = cipher.encrypt(pad(message_bytes, DES3.block_size))
                                elif encryption_option.get() == 2:
                                    print("AES128")

                                    cipher = AES.new(session_key, AES.MODE_ECB)
                                    if signature_var.get():
                                        signature_message_bytes = (json.dumps(signature_message)).encode('utf-8')
                                        padded_plaintext = pad(signature_message_bytes, AES.block_size)
                                        ciphertext = cipher.encrypt(padded_plaintext)
                                    else:
                                        padded_plaintext = pad(message_bytes, AES.block_size)
                                        ciphertext = cipher.encrypt(padded_plaintext)

                                    print(f'Ciphertext: {ciphertext.hex()}')


        if compress_var.get():
            if encryption_option.get() == 1 or encryption_option.get() == 2:
                ciphertext = zlib.compress(ciphertext)
            else:
                print("pre compress")
                print(message_bytes)
                message_bytes = zlib.compress(message_bytes)
                print("post compress")
                print(message_bytes)

            if signature_var.get():
                signature = zlib.compress(signature)

        if radix64_var.get():
            message_bytes = base64.b64encode(message_bytes)

        with open(file_path_string, mode='wb') as file:
            if compress_var.get():
                file.write("zip compress".encode('utf-8'))
                file.write(b"\n")

            if signature is not None:
                file.write("signature".encode('utf-8'))
                file.write(b"\n")
                print("SIGNATURE SEND")
                print(signature)
                encoded_signature = base64.b64encode(signature)
                file.write(encoded_signature)
                file.write(b"\n")

                file.write("sender key id".encode('utf-8'))
                file.write(b"\n")
                file.write(str(key_id_sender).encode('utf-8'))
                file.write(b"\n")

            file.write("message".encode('utf-8'))
            file.write(b"\n")
            if encryption_option.get() == 1 or encryption_option.get() == 2:
                encoded_ciphertext = base64.b64encode(ciphertext)
                file.write(encoded_ciphertext)
                file.write(b"\n")

                file.write("encryption algorithm".encode('utf-8'))
                file.write(b"\n")

                if encryption_option.get() == 1:
                    file.write("TripleDES".encode('utf-8'))
                    file.write(b"\n")
                elif encryption_option.get() == 2:
                    file.write("AES128".encode('utf-8'))
                    file.write(b"\n")

                file.write("session key component".encode('utf-8'))
                file.write(b"\n")
                encoded_session_key = base64.b64encode(session_key_ciphertxt)
                file.write(encoded_session_key)
                file.write(b"\n")

                file.write("recipient key id".encode('utf-8'))
                file.write(b"\n")
                file.write(str(recipient_key_id).encode('utf-8'))
                file.write(b"\n")

            else:
                encoded_message_bytes = base64.b64encode(message_bytes)
                file.write(encoded_message_bytes)
                file.write(b"\n")


def private_key_decrypt(enc_private_key, index):
    global logged_user
    global ivs

    digest = hashes.Hash(hashes.SHA1())
    digest.update(logged_user.password)
    hash_value = digest.finalize()
    cast_key = hash_value[:16]  # CAST-128 key must be between 5 and 16 bytes

    iv = None

    for elem in ivs:
        if elem.user_id == logged_user.email:
            iv = elem.values[index]
            break


    # Step 2: Create the CAST-128 cipher with the IV
    cipher = CAST.new(cast_key, CAST.MODE_CBC, iv)

    # Step 3: Decrypt the private key
    decrypted_private_key_padded = cipher.decrypt(enc_private_key)

    # Step 4: Unpad the decrypted private key data
    decrypted_private_key = unpad(decrypted_private_key_padded, CAST.block_size)

    # Step 5: Deserialize the decrypted private key back into a private key object
    private_key = serialization.load_pem_private_key(
        decrypted_private_key,
        password=None,  # Since there's no password on the PEM-encoded key
    )

    return private_key


def receive_msg_action(file_path, save_file_path):
    # kad korisnik prima poruku
    global logged_user
    global tripledes_iv
    # provera da li je odradjena tajnost

    enc_message = None
    enc_session_key = None
    recipient_key_id = None
    alg = None
    signature = None
    sender_key_id = None
    compress_zip = False

    with open(file_path, mode='rb') as file:
        lines = file.readlines()

        for i, line in enumerate(lines):

            if b"zip compress" in line:
                compress_zip = True

            if b"message" in line:
                enc_message = base64.b64decode(lines[i + 1].strip())
                if compress_zip is True:
                    enc_message = zlib.decompress(enc_message)

            if b"session key component" in line:
                enc_session_key = base64.b64decode(lines[i + 1].strip())

            if b"recipient key id" in line:
                recipient_key_id = lines[i + 1].strip()
                key_id_str = recipient_key_id.decode('utf-8')

                key_id_int = int(key_id_str)

            if b"encryption algorithm" in line:
                alg = lines[i + 1].strip().decode('utf-8')

            if b"signature" in line:
                signature = base64.b64decode(lines[i + 1].strip())

            if b"sender key id" in line:
                sender_key_id = lines[i + 1].strip()
                sender_key_id_str = sender_key_id.decode('utf-8')

                sender_key_id_int = int(sender_key_id_str)


        if enc_message:
            print(f"Message (ciphertext): {enc_message}")
        else:
            print("No message found.")

        # if compress_zip:
        #     if enc_message:
        #         enc_message = zlib.decompress(enc_message)
        #     if signature:
        #         signature = zlib.decompress(signature)

        if enc_session_key:
            enc_private_key = None
            index = -1

            for private_key_ring in private_key_rings:
                if private_key_ring.get_user_id() == logged_user.email:

                    for i, d in enumerate(private_key_ring.user_keys):
                        rec_key_id_int = int(recipient_key_id.decode('utf-8'))
                        if d.get('key_id') == rec_key_id_int:
                            enc_private_key = d.get('private_key')
                            index = i
                            break

            private_key = private_key_decrypt(enc_private_key, index)

            # DEKRIPCIJA

            session_key_plaintext = private_key.decrypt(
                enc_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            plaintext = None

            if alg == "TripleDES":
                if tripledes_iv is not None:
                    cipher_decrypt = DES3.new(session_key_plaintext, DES3.MODE_CBC, iv=tripledes_iv)
                    plaintext = unpad(cipher_decrypt.decrypt(enc_message), DES3.block_size)

                    print(plaintext)
            elif alg == "AES128":
                decipher = AES.new(session_key_plaintext, AES.MODE_ECB)
                decrypted_padded_plaintext = decipher.decrypt(enc_message)
                plaintext = unpad(decrypted_padded_plaintext, AES.block_size)

                print(f'Decrypted Plaintext: {plaintext.decode()}')
        else:
            plaintext = enc_message
            print("PLAINTEXT")
            print(plaintext)

        if signature:
            #AUTENTIKACIJA

            found = False
            public_key = None

            for ring in public_key_rings:
                for elem in ring.keys:
                    if elem["key_id"] == sender_key_id_int:
                        public_key = elem["public_key"]
                        found = True
                        break

                if found:
                    break

            digest = hashes.Hash(hashes.SHA1())

            # Dodavanje podataka koje želite da heširate
            print("Message bytes receive")
            print(enc_message)
            print("Length receive")
            print(len(enc_message))
            digest.update(enc_message)

            # Dobijanje heš vrednosti
            hashed_message = digest.finalize()

            print("Receive")
            print(hashed_message)

            print("SIGNATURE RECEIVE")
            print(signature)

            print("PUBLIC KEY RECEIVE")
            print(public_key)

            #3. Verifikacija potpisa pomoću javnog ključa
            try:
                public_key.public_key().verify(
                    signature,
                    enc_message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Potpis je validan. Poruka je autentična.")
                with open(save_file_path.get(), mode='wb') as file:
                    decoded_message = plaintext.decode('utf-8')
                    file.write(json.loads(decoded_message)["data"].encode('utf-8'))
            except Exception as e:
                print(f"Tip izuzetka: {type(e).__name__}")
                print(f"Poruka izuzetka: {e}")
                print("Potpis nije validan. Poruka možda nije autentična ili je izmenjena.")



def import_keys_action(filepath):
    print("Import keys button clicked")

    with open(filepath, "rb") as file:
        key_data = file.read()

    # Odvajanje privatnog i javnog ključa (ako su u istom fajlu)
    private_key_pem = key_data.split(b"-----END RSA PRIVATE KEY-----")[0] + b"-----END RSA PRIVATE KEY-----"
    public_key_pem = key_data.split(b"-----END PUBLIC KEY-----")[0].split(b"-----END RSA PRIVATE KEY-----")[1] + b"-----END PUBLIC KEY-----"

    # Deserializacija privatnog ključa
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Deserializacija javnog ključa
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    logged_user.add_key_pair(private_key, public_key)

    for ring in private_key_rings:
        if ring.user_id == logged_user.email:
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Kreiranje key id
            # Konvertovanje bajtova u integer (bajtova niz u broj)
            public_key_int = int.from_bytes(public_key_bytes, byteorder='big')
            # Izdvajanje poslednjih 64 bita
            key_id = public_key_int & ((1 << 64) - 1)

            ring.add_key(time.time(), key_id, public_key, private_key)

            ring.print_ring()
            break


def export_keys_action(username, public_key, private_key, option):
    print("Export keys button clicked")

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    for export in num_of_exports:
        if export["username"] == username:
            export["num"] = export["num"] + 1

            filename = username + " export " + str(export["num"]) + ".txt"
            current_directory = os.path.dirname(os.path.abspath(__file__))
            user_directory = os.path.join(current_directory, username)
            export_directory = os.path.join(user_directory, "export")
            file_path = os.path.join(export_directory, filename)

            print(file_path)

            with open(file_path, mode='wb') as file:
                if option == "Javni i privatni":
                    file.write(private_pem)
                file.write(public_pem)

            break


def log_out_action():
    global logged_user
    print("Log out button clicked")
    logged_user = None

if __name__ == '__main__':
    print("Can't run this file. Try main.py")