import tkinter as tk
import rsa
import hashlib
import csv
import time
from tkinter import messagebox
from Crypto.Cipher import CAST

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

# private_key = None

def generate_keys(name, email, selected_option):
    if not name.get().strip() or name.get() == '.' or not email.get().strip() or email.get() == '.':
        tk.messagebox.showerror("Greska", "Unesite sve podatke")
    else:
        (public_key, private_key) = rsa.newkeys(int(selected_option.get()))
        password_input(private_key, public_key, email)


def password_button_click(password, private_key, public_key, email):
    print(email)
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
        submit_button = tk.Button(root, text="Generisi kljuceve", command=login)
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

    password_button = tk.Button(root, text="Generisi kljuceve", command=lambda:password_button_click(password.get(), private_key, public_key, email_get))
    password_button.pack(pady=20)

    return password




login()
root.mainloop()
