import tkinter as tk
from tkinter import ttk
import rsa
import hashlib
import time
import re
from tkinter import messagebox, filedialog, ttk
from Crypto.Cipher import CAST, DES3, AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
import pem
import base64
import ast
import csv
import gzip
import codecs
from Crypto.Random import get_random_bytes
from Crypto.IO.PEM import encode, decode


from Crypto.Util.Padding import unpad

private_key_ring = {}
public_key_ring = {}
users = []
logged_user = None
generated_keys = None


root = tk.Tk()

selected_option_alg = tk.IntVar()


root.title("PGP")
root.geometry("700x700")


def register():
    clear_window()

    # name_frame = tk.Frame(root)
    # name_frame.pack(pady=10)
    #
    # name_label = tk.Label(name_frame, text="Name: ")
    # name_label.pack(side=tk.LEFT)
    #
    # name = tk.Entry(name_frame)
    # name.pack(side=tk.LEFT)

    name_label = tk.Label(root, text="Name: ")
    name_label.pack()

    name = tk.Entry(root)
    name.pack(pady=10)

    email_label = tk.Label(root, text="Email: ")
    email_label.pack()

    email = tk.Entry(root)
    email.pack(pady=10)

    password_label = tk.Label(root, text="Password: ")
    password_label.pack()

    password = tk.Entry(root, show="*")
    password.pack(pady=10)

    register_click_button = tk.Button(root, text="Register user", command=lambda:register_click(name.get(), email.get(), password.get()))
    register_click_button.pack(pady=20)


def register_click(name, email, password):
    global logged_user
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    msg_label = tk.Label(root)

    if not name.strip() or name == '.' or not email.strip() or email == '.' or not password.strip() or password == '.':
        msg_label.config(text="All fields are mandatory.")
    elif not re.fullmatch(pattern, email):
        msg_label.config(text="Invalid format for email address.")
    else:
        hashed_password = text_hashing(password)

        logged_user = {"name": name, "email": email, "password": hashed_password}

        users.append(logged_user)

    msg_label.pack(pady=10)


def login():
    clear_window()

    email_label = tk.Label(root, text="Imejl: ")
    email_label.pack()

    email = tk.Entry(root)
    email.pack(pady=10)

    password_label = tk.Label(root, text="Password: ")
    password_label.pack()

    password = tk.Entry(root, show="*")
    password.pack(pady=10)

    login_click_button = tk.Button(root, text="Dalje", command=lambda:login_click(email.get(), password.get()))
    login_click_button.pack(pady=20)


def login_click(email, password):
    global logged_user
    msg_label = tk.Label(root)

    if not email.strip() or email == '.' or not password.strip() or password == '.':
        msg_label.config(text="All fields are mandatory.")
    hashed_password = text_hashing(password)

    found = False

    for user in users:
        if user["email"] == email and user["password"] == hashed_password:
            logged_user = user
            found = True
            break

    if not found:
        msg_label.config(text="User not found. Try again!")
    else:
        msg_label.config(text="You successfully logged in!")
    msg_label.pack()


def log_out():
    global logged_user
    logged_user = None


def generate_keys():
    global logged_user
    clear_window()

    msg_label = tk.Label(root)

    # print(logged_user)

    if logged_user == None:
        msg_label.config(text="You are not logged in.")

    msg_label.pack()

    options = ["1024", "2048"]
    selected_option = tk.StringVar()
    selected_option.set(options[0])

    option_menu_label = tk.Label(root, text="Velicina kljuca:")
    option_menu_label.pack()

    option_menu = tk.OptionMenu(root, selected_option, *options)
    option_menu.pack(pady=10)

    generate_keys_click_button = tk.Button(root, text="Next", command=lambda: generate_keys_click(selected_option.get()))
    generate_keys_click_button.pack(pady=20)

    #export_keys_pem(private_key, public_key, name.get())
    #password_input(private_key, public_key, email)


def generate_keys_click(selected_option):
    global logged_user
    public_key, private_key = rsa.newkeys(int(selected_option))

    print(public_key)
    print(private_key)

    cipher = CAST.new(logged_user["password"][:16], CAST.MODE_OPENPGP)
    private_key_bytes = rsa.key.PrivateKey.save_pkcs1(private_key)
    ciphered_private_key = cipher.encrypt(private_key_bytes)

    update_private_key_ring(logged_user["email"], ciphered_private_key, public_key, logged_user["password"])
    update_public_key_ring(logged_user["email"], public_key)


def update_private_key_ring(email, private_key, public_key, password):
    # public_key_bytes = rsa.key.PublicKey.save_pkcs1(public_key)
    der_public_key = public_key.save_pkcs1(format='DER')
    least_significant_8_bytes = der_public_key[-8:]

    # found = False
    #
    # if email in private_key_ring:
    #     private_key_ring[email]["timestamp"] = time.time()
    #     private_key_ring[email]["key_id"] = least_significant_8_bytes
    #     private_key_ring[email]["public_key"] = public_key
    #     private_key_ring[email]["private_key"] = private_key
    #     private_key_ring[email]["password"] = password
    #
    #     found = True

    if email not in private_key_ring:
        private_key_ring[email] = []

    private_key_ring[email].append({"timestamp": time.time(), "key_id": least_significant_8_bytes, "public_key": public_key,
               "private_key": private_key, "email": email, "password": password})

    print("Private key ring: " + str(private_key_ring) + "\n")


def update_public_key_ring(email, public_key):
    der_public_key = public_key.save_pkcs1(format='DER')
    least_significant_8_bytes = der_public_key[-8:]

    if email not in public_key_ring:
        public_key_ring[email] = []

    public_key_ring[email].append({"timestamp": time.time(), "key_id": least_significant_8_bytes, "public_key": public_key, "email": email})

    print("Public key ring: " + str(public_key_ring) + "\n")


def text_hashing(text):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(text.encode('utf-8'))

    hashed_text = sha1_hash.digest()

    return hashed_text


def add_padding(base64_string):
    missing_padding = len(base64_string) % 4
    if missing_padding != 0:
        base64_string += '=' * (4 - missing_padding)
    return base64_string


def import_key():
    global logged_user

    clear_window()

    msg_label = tk.Label(root)

    if not logged_user:
        msg_label.config(text="User must be logged in.")
    else:
        file_path = filedialog.askopenfilename(
            title="Odaberi fajl",
            filetypes=(("Tekst fajlovi", "*.txt"), ("Svi fajlovi", "*.*"))
        )

        if file_path:
            pem_file = pem.parse_file(file_path)
            found = False
            user = None

            for elem in private_key_ring.items():
                if elem[0] == logged_user["email"]:
                    found = True
                    user = elem[1]
                    break

            if not found:
                if len(pem_file) == 2:
                    password_window_click()
                    private_key_pem = decode(str(pem_file[0]))[0]

                    public_key_pem = pem_file[1].as_bytes()
                    public_key_object = rsa.PublicKey.load_pkcs1(public_key_pem, format='PEM')

                    update_private_key_ring(logged_user["email"], private_key_pem, public_key_object, logged_user["password"])
                    update_public_key_ring(logged_user["email"], public_key_object)
                else:
                    msg_label.config(text="User not found.")
                    msg_label.pack(pady=10)

                return

            # nemamo slucaj ako je import kljuceva zapravo prvo dodavanje kljuceva u sistem
            # sta se onda radi za private key ako korisnik zeli da importuje samo public key ?
            # kad importujemo i public i private key, da li treba da zatrazimo unos lozinke u sistem
            # kako bi se proverilo zbog menjanja tajnog kljuca?

            if found and len(pem_file) == 1:
                public_key_pem = pem_file[0].as_bytes()
                public_key_object = rsa.PublicKey.load_pkcs1(public_key_pem, format='PEM')

                update_private_key_ring(user["email"], user["private_key"], public_key_object, user["password"])
                update_public_key_ring(user["email"], public_key_object)
                print(private_key_ring)

                return None, public_key_object
            elif found:
                password_window_click()
                private_key_pem = decode(str(pem_file[0]))[0]


                # DODALA SAM SIFROVANJE PRIVATNOG KLJUCA
                # cipher = CAST.new(logged_user["password"][:16], CAST.MODE_OPENPGP)
                # private_key_bytes = rsa.key.PrivateKey.save_pkcs1(private_key_object)
                # ciphered_private_key = cipher.encrypt(private_key_bytes)

                public_key_pem = pem_file[1].as_bytes()
                public_key_object = rsa.PublicKey.load_pkcs1(public_key_pem, format='PEM')

                # ovoga nije bilo ??? mi nismo ni menjali private key ring kad dodaje oba ???
                update_private_key_ring(user["email"], private_key_pem, public_key_object, user["password"])
                update_public_key_ring(user["email"], public_key_object)
                print(private_key_ring)

                #password_input(private_key_object, public_key_object, email)

                return private_key_pem, public_key_object
    msg_label.pack(pady=10)

def password_window_click():
    password_window = tk.Toplevel(root)
    password_window.geometry("300x300")
    password_window.title("Password")

    password_label = tk.Label(password_window)
    password_label.pack(pady=10)

    password = tk.Entry(password_window, show="*")
    password.pack(pady=10)

    password_button = tk.Button(password_window, text="Check", command=lambda: check_password(password.get(), password_window))
    password_button.pack(pady=10)

def check_password(password, password_window):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(password.encode('utf-8'))

    hashed_password = sha1_hash.digest()

    error_label = tk.Label(password_window)

    if hashed_password != logged_user["password"]:
        error_label.config(text="Wrong password")
        error_label.pack(pady= 10)
    else:
        password_window.destroy()


def export_keys():
    global logged_user

    clear_window()

    msg_label = tk.Label(root)

    if not logged_user:
        msg_label.config(text="User must be logged in.")
    else:

        found = False
        user = None

        for elem in private_key_ring.items():
            if elem[0] == logged_user["email"]:
                found = True
                user = elem[1]
                break

        export_options = ["Private and public keys", "Public key"]
        export_selected_option = tk.StringVar()
        export_selected_option.set(export_options[0])

        option_menu_export_label = tk.Label(root, text="Choose how you want keys to be exported:")
        option_menu_export_label.pack()

        option_menu_export = tk.OptionMenu(root, export_selected_option, *export_options)
        option_menu_export.pack(pady=10)

        # da li treba pitati za sifru u slucaju exportovanja privatnog kljuca?


        private_key_pem = encode(user["private_key"], "RSA PRIVATE KEY")
        public_key_pem = user["public_key"].save_pkcs1().decode('utf-8')

        export_button = tk.Button(root, text="Export", command=lambda: export_keys_pem(private_key_pem if export_selected_option.get() == "Private and public keys" else None,
            public_key_pem, logged_user["name"]))
        export_button.pack(pady=20)

    msg_label.pack(pady=10)


def export_keys_pem(private_key, public_key, name):
    with open(name + ".pem", 'w') as priv_file:
        if private_key:
            priv_file.write(private_key)
            priv_file.write("\n")
        priv_file.write(public_key)

def show_keys():
    clear_window()

    private_key_ring_table_frame = ttk.Frame(root)
    private_key_ring_table_frame.pack(pady=20)

    columns = ('email', 'public_key', 'private_key')

    private_key_ring_table = ttk.Treeview(private_key_ring_table_frame, columns=columns, show='headings')

    private_key_ring_table.heading('email', text='Email')
    private_key_ring_table.heading('public_key', text='Public Key')
    private_key_ring_table.heading('private_key', text='Private Key')

    # OVO TREBA DA SE PROMENI KAD BUDEMO STAVLJALI DA MEJL MOZE DA IMA VISE KLJUCEVA, TO TI URADI PLS
    if logged_user and len(private_key_ring) > 0:
        for item in private_key_ring[logged_user["email"]]:
            private_key_ring_table.insert('', tk.END, values=(item["email"], item["public_key"], item["private_key"]))

    private_key_ring_table.pack()

    private_key_ring_table.bind('<ButtonRelease-1>')

    public_key_ring_table_frame = ttk.Frame(root)
    public_key_ring_table_frame.pack(pady=20)

    columns = ('email', 'public_key')

    public_key_ring_table = ttk.Treeview(public_key_ring_table_frame, columns=columns, show='headings')

    public_key_ring_table.heading('email', text='Email')
    public_key_ring_table.heading('public_key', text='Public Key')

    if logged_user and len(public_key_ring) > 0:
        for user in public_key_ring.keys():
            for key in public_key_ring[user]:
                if key["email"] != logged_user["email"]:
                    public_key_ring_table.insert('', tk.END, values=(key["email"], key["public_key"]))

    public_key_ring_table.pack()

    public_key_ring_table.bind('<ButtonRelease-1>')


def on_cell_click(event, table):
    row_id = table.identify_row(event.y)

    if row_id:
        item = table.item(row_id)
        email = item['values'][0]
        private_key = item['values'][2]

        new_window = tk.Toplevel()
        new_window.title("Sifra za privatni kljuc")
        new_window.geometry("600x400")

        password_label = tk.Label(new_window, text="Sifra: ")
        password_label.pack()

        password = tk.Entry(new_window)
        password.pack(pady=10)

        check_button = tk.Button(new_window, text="Proveri sifru", command=lambda: check_password(password.get(), email, private_key, new_window))
        check_button.pack(pady=20)


def password_button_click(password, email, selected_option, name, key_size):
    if not password.strip() or password == '.':
        tk.messagebox.showerror("Greska", "Unesite trazenu sifru.")
    else:
        sha1_hash = hashlib.sha1()
        sha1_hash.update(password.encode('utf-8'))

        hashed_password = sha1_hash.digest()

        cipher = CAST.new(hashed_password[:16], CAST.MODE_OPENPGP)

        if selected_option.get() == "Generisi kljuc":
            public_key, private_key = generate_keys(name, email, key_size)
        else:
            private_key, public_key = import_key(name, email)

        clear_window()

        if private_key:
            print("privatni kljuc: ")
            print(private_key)
            private_key_bytes = rsa.key.PrivateKey.save_pkcs1(private_key)

            ciphered_private_key = cipher.encrypt(private_key_bytes)

            update_private_key_ring(email, ciphered_private_key, public_key, hashed_password)

        update_public_key_ring(email, public_key)

        table_frame = ttk.Frame(root)
        table_frame.pack(pady=20)

        columns = ('email', 'public_key', 'private_key')

        table = ttk.Treeview(table_frame, columns=columns, show='headings')

        table.heading('email', text='Email')
        table.heading('public_key', text='Public Key')
        table.heading('private_key', text='Private Key')

        for item in private_key_ring:
            table.insert('', tk.END, values=(item['email'], item['public_key'], item['private_key']))

        table.pack()

        table.bind('<ButtonRelease-1>', lambda event: on_cell_click(event, table))

        export_options = ["Privatni i javni kljuc", "Javni kljuc"]
        export_selected_option = tk.StringVar()
        export_selected_option.set(export_options[0])

        option_menu_export_label = tk.Label(root, text="Izaberite nacin izvoza kljuceva:")
        option_menu_export_label.pack()

        option_menu_export = tk.OptionMenu(root, export_selected_option, *export_options)
        option_menu_export.pack(pady=10)

        export_button = tk.Button(root, text="Izvezi kljuceve", command=lambda: export_keys_pem(private_key if export_selected_option.get() == "Privatni i javni kljuc" else None, public_key, name))
        export_button.pack(pady=20)

        submit_button = tk.Button(root, text="Vrati se nazad", command=register)
        submit_button.pack(pady=20)



def clear_window():
    for widget in root.winfo_children():
        if widget.winfo_class() == 'Frame':
            continue
        # if widget.winfo_class() == 'Button' and (widget.cget("text") == 'Register' or widget.cget("text") == 'Login' or widget.cget("text") == 'Generate keys' or widget.cget("text") == 'Log out'):
        #     continue
        widget.destroy()


def password_input(name, email, key_size):
    email_get = email.get()
    clear_window()

    password_label = tk.Label(root, text="Sifra: ")
    password_label.pack()

    password = tk.Entry(root)
    password.pack()

    options = ["Generisi kljuc", "Uvezi kljuc"]
    selected_option = tk.StringVar()
    selected_option.set(options[0])

    option_menu_label = tk.Label(root, text="Izaberite nacin kreiranja kljuca:")
    option_menu_label.pack()

    option_menu = tk.OptionMenu(root, selected_option, *options)
    option_menu.pack(pady=10)

    password_button = tk.Button(root, text="Enkriputj privatni kljuc", command=lambda:password_button_click(password.get(), email_get, selected_option, name, key_size))
    password_button.pack(pady=20)

    return password


def send_message():
    global selected_option_alg
    def enable_disable_radiobuttons():
        if encryption_checked.get():
            tripledes_check_button.config(state='normal')
            aes_check_button.config(state='normal')
        else:
            tripledes_check_button.config(state='disabled')
            aes_check_button.config(state='disabled')

    def enable_disable_signature():
        if signature_checked.get():
            private_key_entry.config(state='normal')
        else:
            private_key_entry.config(state='disabled')

    clear_window()

    file_name_label = tk.Label(root, text="File name")
    file_name_label.pack(pady=10)

    file_name = tk.Entry(root)
    file_name.pack(pady=10)

    file_path_label = tk.Label(root, text="File path")
    file_path_label.pack(pady=10)

    file_path = tk.Entry(root)
    file_path.pack(pady=10)

    encryption_checked = tk.BooleanVar(value=False)
    signature_checked = tk.BooleanVar(value=False)
    

    encryption_check_button = ttk.Checkbutton(root, text="Encryption", variable=encryption_checked, command=enable_disable_radiobuttons)
    tripledes_check_button = ttk.Radiobutton(root, text="TripleDES", variable=selected_option_alg, value=1, state='disabled')
    aes_check_button = ttk.Radiobutton(root, text="AES128", variable=selected_option_alg, value=2, state='disabled')

    encryption_check_button.pack()
    tripledes_check_button.pack()
    aes_check_button.pack()

    options = []
    selected_option = tk.StringVar()

    for user in public_key_ring.keys():
        if logged_user["email"] != user:
            for key in public_key_ring[user]:
                options.append(user + " " + str(key["key_id"]))



    if len(options) > 0:
        selected_option.set(options[0])
    else:
        selected_option.set("No public keys")
        options.append("No public keys")

    option_menu_label = tk.Label(root, text="Public key:")
    option_menu_label.pack()

    option_menu = tk.OptionMenu(root, selected_option, *options)
    option_menu.config(width=50)
    option_menu.pack(pady=10)


    signature_check_button = ttk.Checkbutton(root, text="Signature", variable=signature_checked, command= enable_disable_signature)
    signature_check_button.pack()

    private_key_entry = tk.Entry(root, state='disabled')
    private_key_entry.pack(pady=10)

    compress_checked = tk.BooleanVar(value=False)
    compress_check_button = ttk.Checkbutton(root, text="Compress", variable=compress_checked)
    compress_check_button.pack()

    print(compress_checked.get())

    conversion_checked = tk.BooleanVar(value=False)
    conversion_check_button = ttk.Checkbutton(root, text="Convert to radix-64", variable=conversion_checked)
    conversion_check_button.pack()

    message_text = tk.Text(root, width=40, height=10)
    message_text.pack(pady=10)

    send_message_button = tk.Button(root, text="Send Message", command=lambda: send_message_click(encryption_checked.get(), signature_checked.get(), compress_checked.get(), conversion_checked.get(),
                                                                                                  file_name.get(), file_path.get(),
                                                                                                    message_text.get("1.0", tk.END), private_key_entry.get(), selected_option.get().split(' ')[1]))
    send_message_button.pack(pady=10)


nonce = get_random_bytes(15)

def send_message_click(encryption_checked, signature_checked, compress_checked, conversion_checked, file_name, file_path, message, private_key, public_key):
    global selected_option_alg, nonce
    if message.endswith('\n'):
        message = message[:-1]

    print("SEND MESSAGE")
    data = [
        ['timestamp', 'filename', 'signature', 'data', 'encryption'],
        [time.time(), file_name]
    ]

    filename = file_path + "\\" + file_name

    signature_data = []
    encryption_data = []
    compressed_data = None

    if signature_checked:
        timestamp = time.time()
        to_hash = message + "" + str(timestamp)
        #hashed_data = text_hashing(to_hash)

        print(private_key)

        eiv = private_key.encode('utf-8')[:CAST.block_size + 2]
        ciphertext = private_key.encode('utf-8')[CAST.block_size + 2:]
        decipher = CAST.new(logged_user["password"][:16], CAST.MODE_OPENPGP, eiv)

        print(type(decipher))
        print(type(ciphertext))
        decrypted_key_bytes = decipher.decrypt(ciphertext)
        print("Dekriptovani privatni kljuc:")
        print(decrypted_key_bytes)
        #print(type(decrypted_key_bytes.decode("utf-8")))
        # print(base64.encodebytes(decrypted_key_bytes))

        # private_key_pem = encode(base64.encodebytes(decrypted_key_bytes), "RSA PRIVATE KEY")
        # print(private_key_pem)
        # private_key_object = rsa.PrivateKey.load_pkcs1(decrypted_key_bytes, format='DER')

        # pem_header = b'-----BEGIN RSA PRIVATE KEY-----\n'
        # pem_footer = b'-----END RSA PRIVATE KEY-----'
        # pem_content = pem_header + base64.encodebytes(decrypted_key_bytes) + pem_footer

        # Ovde je jednostavan primer sa dummy vrednostima
        n = int.from_bytes(decrypted_key_bytes[:256], 'big')
        e = int.from_bytes(decrypted_key_bytes[256:260], 'big')
        d = int.from_bytes(decrypted_key_bytes[260:516], 'big')
        p = int.from_bytes(decrypted_key_bytes[516:644], 'big')
        q = int.from_bytes(decrypted_key_bytes[644:772], 'big')
        dmp1 = int.from_bytes(decrypted_key_bytes[772:900], 'big')
        dmq1 = int.from_bytes(decrypted_key_bytes[900:1028], 'big')
        iqmp = int.from_bytes(decrypted_key_bytes[1028:], 'big')

        # Kreiranje PrivateKey objekta
        private_key_object = rsa.PrivateKey(n, e, d, p, q)

        # decrypted_private_key = rsa.PrivateKey.load_pkcs1(pem_content)

        # crypto = rsa.encrypt(hashed_data, private_key_object)
        # hash = rsa.compute_hash(to_hash.encode(), 'SHA-1')
        crypto = rsa.sign(to_hash.encode(), private_key_object, 'SHA-1')

        # hash_message = private_key_object.sign(
        #     bytes(to_hash, 'ascii'),
        #     padding.PSS(
        #         mgf=padding.MGF1(hashes.SHA1()),
        #         salt_length=padding.PSS.MAX_LENGTH
        #     ),
        #     hashes.SHA1()
        # )

        # print(hash_message)

        print(public_key_ring[logged_user["email"]])
        key_id = None
        for item in private_key_ring[logged_user["email"]]:
            print(item["private_key"])
            print(private_key)
            if(str(item["private_key"]) == str(private_key)):
                key_id = item["key_id"]
                break

        signature_data = [timestamp, key_id, crypto[:2], crypto]
        data[1].append(signature_data)

    if encryption_checked:
        session_key = get_random_bytes(16)
        timestamp = time.time()
        message_to_encrypt = message + "" + str(timestamp)

        salt = get_random_bytes(16)

        cipher = None

        if selected_option_alg.get() == 1:
            key = PBKDF2(session_key, salt, dkLen=24)
            cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
        elif selected_option_alg.get() == 2:
            key = PBKDF2(session_key, salt, dkLen=16)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

        ciphertext, tag = cipher.encrypt_and_digest(message_to_encrypt.encode())
        encrypted_message = (cipher.nonce, tag, ciphertext)
        # encrypted_message = ciphertext

        receiver_public_key = None
        for key in public_key_ring.keys():
            for elem in public_key_ring[key]:
                if str(elem["key_id"]) == str(public_key):
                    receiver_public_key = elem["public_key"]
                    break

        print(receiver_public_key)
        print(type(receiver_public_key))

        print(session_key)

        encrypted_session_key = rsa.encrypt(session_key, receiver_public_key)

        print(encrypted_session_key)
        print(base64.b64encode(encrypted_session_key))

        encryption_data = [encrypted_message, public_key, base64.b64encode(encrypted_session_key)]
    elif not conversion_checked:
        encryption_data = [message]

    data[1].append(encryption_data)

    if compress_checked:
        data_to_compress = str(signature_data) + str(timestamp) + filename + message
        compressed_data = gzip.compress(data_to_compress.encode('utf-8'))

    if conversion_checked:
        if compress_checked:
            compressed_data = base64.b64encode(compressed_data)
        else:
            timestamp = base64.b64encode(timestamp)
            filename = base64.b64encode(filename)
            signature_data = base64.b64encode()

        encryption_data = base64.b64encode(encryption_data)

    with open(filename, 'w', newline='') as file:
        if compressed_data:
            file.write(compressed_data)
        else:
            file.write(str(timestamp) + '\n')
            file.write(filename + '\n')
            file.write(str(signature_data) + '\n')
        file.write(str(encryption_data) + '\n')

def receive_message():
    global nonce
    clear_window()

    file_path = filedialog.askopenfilename(
        title="Odaberi fajl",
        filetypes=(("CSV fajlovi", "*.csv"), ("Svi fajlovi", "*.*"))
    )

    message = []

    if file_path:
        with open(file_path, 'r') as file:
            csv_content = file.readlines()

        encryption_data = csv_content[3]
        encryption_msg = encryption_data.split(", ")[0][1: len(encryption_data.split(',')[0])]
        print(encryption_msg)
        key_id = encryption_data.split(", ")[1][1: len(encryption_data.split(',')[1]) - 2]
        key_id = key_id.replace('\\\\', '\\')
        base_encrypted_key_session = encryption_data.split(', ')[2][1: len(encryption_data.split(',')[2]) - 3]
        print(base_encrypted_key_session)
        encrypted_key_session = base64.b64decode(base_encrypted_key_session)

        private_key = None
        for item in private_key_ring[logged_user["email"]]:
            print(item["key_id"])
            print(key_id)
            if str(item["key_id"]) == str(key_id):
                private_key = item["private_key"]
                break

        eiv = private_key[:CAST.block_size + 2]
        ciphertext = private_key[CAST.block_size + 2:]
        decipher = CAST.new(logged_user["password"][:16], CAST.MODE_OPENPGP, eiv)

        print(type(decipher))
        print(type(ciphertext))
        decrypted_key_bytes = decipher.decrypt(ciphertext)
        print("Dekriptovani privatni kljuc:")
        print(decrypted_key_bytes)
        #print(type(decrypted_key_bytes.decode("utf-8")))
        # print(base64.encodebytes(decrypted_key_bytes))

        # private_key_pem = encode(base64.encodebytes(decrypted_key_bytes), "RSA PRIVATE KEY")
        # print(private_key_pem)
        private_key_object = rsa.PrivateKey.load_pkcs1(decrypted_key_bytes, format='PEM')
        print(private_key_object)

        # pem_header = b'-----BEGIN RSA PRIVATE KEY-----\n'
        # pem_footer = b'-----END RSA PRIVATE KEY-----'
        # pem_content = pem_header + base64.encodebytes(decrypted_key_bytes) + pem_footer

        # Ovde je jednostavan primer sa dummy vrednostima
        n = int.from_bytes(decrypted_key_bytes[:256], 'big')
        e = int.from_bytes(decrypted_key_bytes[256:260], 'big')
        d = int.from_bytes(decrypted_key_bytes[260:516], 'big')
        p = int.from_bytes(decrypted_key_bytes[516:644], 'big')
        q = int.from_bytes(decrypted_key_bytes[644:772], 'big')
        dmp1 = int.from_bytes(decrypted_key_bytes[772:900], 'big')
        dmq1 = int.from_bytes(decrypted_key_bytes[900:1028], 'big')
        iqmp = int.from_bytes(decrypted_key_bytes[1028:], 'big')

        # Kreiranje PrivateKey objekta
        # private_key_object = rsa.PrivateKey(n, e, d, p, q)

        # encrypted_key_str = base64.b64encode(encrypted_key_session.encode("utf-8")).decode('utf-8')
        # base = base64.b64decode(encrypted_key_str)
        decrypted_session_key = rsa.decrypt(encrypted_key_session, private_key_object)

        print(decrypted_session_key)

        nonce, tag, ciphertext = encryption_msg
        if(selected_option_alg.get() == 1):
            cipher_decrypt = DES3.new(decrypted_session_key, DES3.MODE_EAX, nonce=nonce)  # you can't reuse an object for encrypting or decrypting other data with the same key.
            # plaintext = cipher_decrypt.decrypt(encryption_msg.encode())

            try:
                plaintext_bytes = cipher_decrypt.decrypt_and_verify(ciphertext, tag)
                plaintext = plaintext_bytes.decode('utf-8')
                print("Decrypted plaintext:", plaintext)
            except ValueError as e:
                print("Decryption failed or message is tampered:", e)
            except UnicodeDecodeError as e:
                print("Failed to decode the decrypted bytes:", e)
        elif (selected_option_alg.get() == 2):
            cipher = AES.new(decrypted_session_key, AES.MODE_EAX)
            plaintext = cipher.decrypt(encryption_msg.encode())

            print(plaintext.decode("ISO-8859-1"))

        #AUTENTIKACIJA
        # print(csv_content)
        # signed_message = csv_content[1][0: len(csv_content[1]) - 1] + "" + csv_content[0][0: len(csv_content[0]) - 1]
        # print(signed_message)
        # msg_signature = csv_content[3].split(',')
        # print(msg_signature)
        # key_id = msg_signature[1][1:]
        # signature = msg_signature[3][1:len(msg_signature[3]) - 2]
        # print(signature)
        # # print(msg_signature)
        #
        # public_key = None
        #
        # for key in public_key_ring.keys():
        #     for item in public_key_ring[key]:
        #         print(key_id)
        #         print(item["key_id"])
        #         if(str(item["key_id"]) == str(key_id)):
        #
        #             public_key = item["public_key"]
        #             break
        #
        # message_hash = rsa.compute_hash(signed_message.encode('utf-8'), 'SHA-1')
        # print(public_key)
        #
        # rsa.verify(signed_message.encode('utf-8'), signature.encode("utf-8"), public_key)

        # public_key.verify(
        #     signature,
        #     signed_message,
        #     padding.PSS(
        #         mgf=padding.MGF1(hashes.SHA1()),
        #         salt_length=padding.PSS.MAX_LENGTH
        #     ),
        #     hashes.SHA1()
        # )

        # print(msg_split)
        # print(msg_split[3])
        # msg_signature = msg_split[3][1: len(msg_split[3])]

        # print(msg_signature)



# def create_message():
#


# login()
button_frame = tk.Frame(root)
button_frame.pack(side=tk.TOP, pady=10)

register_button = tk.Button(button_frame, text="Register", command=register)
register_button.pack(side=tk.LEFT, padx=5, pady=10)

login_button = tk.Button(button_frame, text="Login", command=login)
login_button.pack(side=tk.LEFT, padx=5, pady=10)

generate_keys_button = tk.Button(button_frame, text="Generate keys", command=generate_keys)
generate_keys_button.pack(side=tk.LEFT, padx=5, pady=10)

show_keys_button = tk.Button(button_frame, text="Keys", command=show_keys)
show_keys_button.pack(side=tk.LEFT, padx=5, pady=10)

import_keys_button = tk.Button(button_frame, text="Import keys", command= import_key)
import_keys_button.pack(side=tk.LEFT, padx=5, pady=10)

export_keys_button = tk.Button(button_frame, text="Export keys", command=export_keys)
export_keys_button.pack(side=tk.LEFT, padx=5, pady=10)

send_message_button = tk.Button(button_frame, text="Send message", command=send_message)
send_message_button.pack(side=tk.LEFT, padx=5, pady=10)

receive_message_button = tk.Button(button_frame, text="Receive message", command=receive_message)
receive_message_button.pack(side=tk.LEFT, padx=5, pady=10)

log_out_button = tk.Button(button_frame, text="Log out", command=log_out)
log_out_button.pack(side=tk.LEFT, padx=5, pady=10)

root.mainloop()
