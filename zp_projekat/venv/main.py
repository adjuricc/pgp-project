import tkinter as tk
from tkinter import ttk
import rsa
import hashlib
import time
import re
from tkinter import messagebox, filedialog, ttk
from Crypto.Cipher import CAST
from Crypto.PublicKey import RSA
import pem
import base64
import ast
from Crypto.IO.PEM import encode, decode


from Crypto.Util.Padding import unpad

private_key_ring = {}
public_key_ring = [] # lista recnika
users = []
logged_user = None
generated_keys = None

root = tk.Tk()

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
        hashed_password = password_hashing(password)

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
    hashed_password = password_hashing(password)

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

    cipher = CAST.new(logged_user["password"][:16], CAST.MODE_OPENPGP)
    private_key_bytes = rsa.key.PrivateKey.save_pkcs1(private_key)
    ciphered_private_key = cipher.encrypt(private_key_bytes)

    update_private_key_ring(logged_user["email"], ciphered_private_key, public_key, logged_user["password"])
    update_public_key_ring(logged_user["email"], public_key)


def update_private_key_ring(email, private_key, public_key, password):
    # public_key_bytes = rsa.key.PublicKey.save_pkcs1(public_key)
    der_public_key = public_key.save_pkcs1(format='DER')
    least_significant_8_bytes = der_public_key[-8:]

    found = False

    if email in private_key_ring:
        private_key_ring[email]["timestamp"] = time.time()
        private_key_ring[email]["key_id"] = least_significant_8_bytes
        private_key_ring[email]["public_key"] = public_key
        private_key_ring[email]["private_key"] = private_key
        private_key_ring[email]["password"] = password

        found = True

    if not found:
        my_dict = {}

        my_dict["timestamp"] = time.time()
        my_dict["key_id"] = least_significant_8_bytes
        my_dict["public_key"] = public_key
        my_dict["private_key"] = private_key
        my_dict["email"] = email
        my_dict["password"] = password

        private_key_ring[email] = my_dict

    print(private_key_ring)

def update_public_key_ring(email, public_key):
    der_public_key = public_key.save_pkcs1(format='DER')
    least_significant_8_bytes = der_public_key[-8:]

    found = False

    for i in range(0, len(public_key_ring)):
        if public_key_ring[i]["email"] == email:
            public_key_ring[i]["timestamp"] = time.time()
            public_key_ring[i]["key_id"] = least_significant_8_bytes
            public_key_ring[i]["public_key"] = public_key

            found = True

            break

    if found == False:
        my_dict = {}

        my_dict["timestamp"] = time.time()
        my_dict["key_id"] = least_significant_8_bytes
        my_dict["public_key"] = public_key
        my_dict["email"] = email

        public_key_ring.append(my_dict)

    print(public_key_ring)



def password_hashing(password):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(password.encode('utf-8'))

    hashed_password = sha1_hash.digest()

    return hashed_password


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
        # eiv = user["private_key"][:CAST.block_size + 2]
        # ciphertext = user["private_key"][CAST.block_size + 2:]
        # cipher = CAST.new(logged_user["password"][:16], CAST.MODE_OPENPGP, eiv)
        # decrypted_key = cipher.decrypt(ciphertext)

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

    print(private_key_ring[logged_user["email"]])


    # OVO TREBA DA SE PROMENI KAD BUDEMO STAVLJALI DA MEJL MOZE DA IMA VISE KLJUCEVA, TO TI URADI PLS
    private_key_ring_table.insert('', tk.END, values=(logged_user["email"], private_key_ring[logged_user["email"]]['public_key'], private_key_ring[logged_user["email"]]['private_key']))
    # for item in private_key_ring[logged_user["email"]]:
    #     print(item)
    #     private_key_ring_table.insert('', tk.END, values=(item[0], item[1], item['private_key']))

    private_key_ring_table.pack()

    private_key_ring_table.bind('<ButtonRelease-1>', lambda event: on_cell_click(event, table))

    public_key_ring_table_frame = ttk.Frame(root)
    public_key_ring_table_frame.pack(pady=20)

    columns = ('email', 'public_key')

    public_key_ring_table = ttk.Treeview(public_key_ring_table_frame, columns=columns, show='headings')

    public_key_ring_table.heading('email', text='Email')
    public_key_ring_table.heading('public_key', text='Public Key')

    for item in public_key_ring:
        print(item)
        public_key_ring_table.insert('', tk.END, values=(item["email"], item["public_key"]))

    public_key_ring_table.pack()

    public_key_ring_table.bind('<ButtonRelease-1>', lambda event: on_cell_click(event, table))


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

log_out_button = tk.Button(button_frame, text="Log out", command=log_out)
log_out_button.pack(side=tk.LEFT, padx=5, pady=10)

root.mainloop()
