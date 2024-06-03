import tkinter as tk
import rsa
import hashlib
import time
import re
from tkinter import messagebox, filedialog, ttk
from Crypto.Cipher import CAST
import pem
import base64
import ast


from Crypto.Util.Padding import unpad

private_key_ring = []
public_key_ring = []

root = tk.Tk()

root.title("PGP")
root.geometry("700x700")


def login():
    clear_window()

    name_label = tk.Label(root, text="Ime: ")
    name_label.pack()

    name = tk.Entry(root)
    name.pack(pady=10)

    email_label = tk.Label(root, text="Imejl: ")
    email_label.pack()

    email = tk.Entry(root)
    email.pack(pady=10)

    options = ["1024", "2048"]
    selected_option = tk.StringVar()
    selected_option.set(options[0])

    option_menu_label = tk.Label(root, text="Velicina kljuca:")
    option_menu_label.pack()

    option_menu = tk.OptionMenu(root, selected_option, *options)
    option_menu.pack(pady=10)

    next_button = tk.Button(root, text="Dalje", command=lambda:password_input(name.get(), email, selected_option.get()))
    next_button.pack(pady=20)


def add_padding(base64_string):
    missing_padding = len(base64_string) % 4
    if missing_padding != 0:
        base64_string += '=' * (4 - missing_padding)
    return base64_string


def import_key(name, email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.fullmatch(pattern, email):
        tk.messagebox.showerror("Greska", "Mejl nije u dobrom formatu")
    elif not name.strip() or name == '.' or not email.strip() or email == '.':
        tk.messagebox.showerror("Greska", "Unesite sve podatke")
    else:
        file_path = filedialog.askopenfilename(
            title="Odaberi fajl",
            filetypes=(("Tekst fajlovi", "*.txt"), ("Svi fajlovi", "*.*"))
        )

        if file_path:
            pem_file = pem.parse_file(file_path)
            found = False
            user = None

            if len(pem_file) == 1:
                for elem in private_key_ring:
                    if elem["email"] == email:
                        found = True
                        user = elem
                        break

                if not found:
                    tk.messagebox.showerror("Greska", "Nepostojeci korisnik!")
                else:
                    public_key_pem = pem_file[0].as_bytes()
                    public_key_object = rsa.PublicKey.load_pkcs1(public_key_pem, format='PEM')

                    update_private_key_ring(user["email"], user["private_key"], public_key_object, user["password"])
                    update_public_key_ring(user["email"], public_key_object)

                    return None, public_key_object
            else:
                private_key_pem = pem_file[1].as_bytes()
                private_key_object = rsa.PublicKey.load_pkcs1(private_key_pem, format='PEM')

                public_key_pem = pem_file[1].as_bytes()
                public_key_object = rsa.PublicKey.load_pkcs1(public_key_pem, format='PEM')

                #password_input(private_key_object, public_key_object, email)

                return private_key_object, public_key_object


def export_keys_pem(private_key, public_key, name):
    private_key_pem = private_key.save_pkcs1().decode('utf-8')
    public_key_pem = public_key.save_pkcs1().decode('utf-8')

    with open(name + ".pem", 'w') as priv_file:
        priv_file.write(private_key_pem)
        priv_file.write(public_key_pem)


def generate_keys(name, email, selected_option):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.fullmatch(pattern, email):
        tk.messagebox.showerror("Greska", "Mejl nije u dobrom formatu")
    elif not name.strip() or name == '.' or not email.strip() or email == '.':
        tk.messagebox.showerror("Greska", "Unesite sve podatke")
    else:
        return rsa.newkeys(int(selected_option))
        #export_keys_pem(private_key, public_key, name.get())
        #password_input(private_key, public_key, email)


def check_password(password, email, private_key, new_window):
    for elem in private_key_ring:
        if elem["email"] == email:
            sha1_hash = hashlib.sha1()
            sha1_hash.update(password.encode('utf-8'))

            hashed_password = sha1_hash.digest()

            if hashed_password == elem["password"]:
                private_key_bytes = ast.literal_eval(private_key)
                eiv = private_key_bytes[:CAST.block_size + 2]
                ciphertext = private_key_bytes[CAST.block_size + 2:]
                cipher = CAST.new(hashed_password[:16], CAST.MODE_OPENPGP, eiv)
                decrypted_key = cipher.decrypt(ciphertext)
                print(decrypted_key)


def on_cell_click(event, table):
    row_id = table.identify_row(event.y)

    if row_id:
        item = table.item(row_id)
        email = item['values'][0]
        private_key = item['values'][2]

        new_window = tk.Toplevel()
        new_window.title("Sifra za privatni kljuc")
        new_window.geometry("400x400")

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

        submit_button = tk.Button(root, text="Vrati se nazad", command=login)
        submit_button.pack(pady=20)


def update_private_key_ring(email, private_key, public_key, password):
    # public_key_bytes = rsa.key.PublicKey.save_pkcs1(public_key)
    der_public_key = public_key.save_pkcs1(format='DER')
    least_significant_8_bytes = der_public_key[-8:]

    found = False

    for i in range(0, len(private_key_ring)):
        if private_key_ring[i]["email"] == email:
            private_key_ring[i]["timestamp"] = time.time()
            private_key_ring[i]["key_id"] = least_significant_8_bytes
            private_key_ring[i]["public_key"] = public_key
            private_key_ring[i]["private_key"] = private_key
            private_key_ring[i]["password"] = password

            found = True

            break

    if not found:
        my_dict = {}

        my_dict["timestamp"] = time.time()
        my_dict["key_id"] = least_significant_8_bytes
        my_dict["public_key"] = public_key
        my_dict["private_key"] = private_key
        my_dict["email"] = email
        my_dict["password"] = password

        private_key_ring.append(my_dict)

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


def clear_window():
    for widget in root.winfo_children():
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


login()
root.mainloop()
