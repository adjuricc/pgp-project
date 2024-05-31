import tkinter as tk
import rsa
import hashlib
import time
import re
from tkinter import messagebox, filedialog
from Crypto.Cipher import CAST
import pem
import base64


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

    submit_button = tk.Button(root, text="Generisi kljuceve", command=lambda: generate_keys(name, email, selected_option))
    submit_button.pack(pady=20)

    import_key_button = tk.Button(root, text="Uvezi kljuc", command=lambda: import_key(name, email))
    import_key_button.pack(pady=20)


def add_padding(base64_string):
    missing_padding = len(base64_string) % 4
    if missing_padding != 0:
        base64_string += '=' * (4 - missing_padding)
    return base64_string


def import_key(name, email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.fullmatch(pattern, email.get()):
        tk.messagebox.showerror("Greska", "Mejl nije u dobrom formatu")
    elif not name.get().strip() or name.get() == '.' or not email.get().strip() or email.get() == '.':
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
                    if elem["email"] == email.get():
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
            else:
                private_key_pem = pem_file[1].as_bytes()
                private_key_object = rsa.PublicKey.load_pkcs1(private_key_pem, format='PEM')

                public_key_pem = pem_file[1].as_bytes()
                public_key_object = rsa.PublicKey.load_pkcs1(public_key_pem, format='PEM')

                password_input(private_key_object, public_key_object, email)


def export_keys_pem(private_key, public_key, name):
    private_key_pem = private_key.save_pkcs1().decode('utf-8')
    public_key_pem = public_key.save_pkcs1().decode('utf-8')

    with open(name + ".pem", 'w') as priv_file:
        priv_file.write(private_key_pem)
        priv_file.write(public_key_pem)


def generate_keys(name, email, selected_option):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.fullmatch(pattern, email.get()):
        tk.messagebox.showerror("Greska", "Mejl nije u dobrom formatu")
    elif not name.get().strip() or name.get() == '.' or not email.get().strip() or email.get() == '.':
        tk.messagebox.showerror("Greska", "Unesite sve podatke")
    else:
        (public_key, private_key) = rsa.newkeys(int(selected_option.get()))
        export_keys_pem(private_key, public_key, name.get())
        password_input(private_key, public_key, email)


def password_button_click(password, private_key, public_key, email):
    if not password.strip() or password == '.':
        tk.messagebox.showerror("Greska", "Unesite trazenu sifru.")
    else:
        sha1_hash = hashlib.sha1()
        sha1_hash.update(password.encode('utf-8'))

        hashed_password = sha1_hash.digest()

        cipher = CAST.new(hashed_password[:16], CAST.MODE_OPENPGP)

        private_key_bytes = rsa.key.PrivateKey.save_pkcs1(private_key)

        ciphered_private_key = cipher.encrypt(private_key_bytes)

        clear_window()
        update_private_key_ring(email, ciphered_private_key, public_key, hashed_password)
        update_public_key_ring(email, public_key)
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

    if found == False:
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


def password_input(private_key, public_key, email):
    email_get = email.get()
    clear_window()

    password_label = tk.Label(root, text="Sifra: ")
    password_label.pack()

    password = tk.Entry(root)
    password.pack()

    password_button = tk.Button(root, text="Enkriputj privatni kljuc", command=lambda:password_button_click(password.get(), private_key, public_key, email_get))
    password_button.pack(pady=20)

    return password


login()
root.mainloop()
