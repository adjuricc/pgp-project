import tkinter as tk
import rsa
import hashlib
from tkinter import messagebox
from Crypto.Cipher import CAST

root = tk.Tk()

root.title("PGP")
root.geometry("700x700")

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

# private_key = None

def generate_keys():
    if not name.get().strip() or name.get() == '.' or not email.get().strip() or email.get() == '.':
        tk.messagebox.showerror("Greska", "Unesite sve podatke")
    else:
        (public_key, private_key) = rsa.newkeys(int(selected_option.get()))
        clear_window(private_key)


def password_button_click(password, private_key):
    if not password.strip() or password == '.':
        tk.messagebox.showerror("Greska", "Unesite trazenu sifru.")
    else:
        sha1_hash = hashlib.sha1()
        sha1_hash.update(password.encode('utf-8'))

        hashed_password = sha1_hash.digest()

        cipher = CAST.new(hashed_password[:16], CAST.MODE_OPENPGP)

        private_key_bytes = rsa.key.PrivateKey.save_pkcs1(private_key)

        ciphered_private_key = cipher.encrypt(private_key_bytes)



def clear_window(private_key):
    for widget in root.winfo_children():
        widget.destroy()

    password_label = tk.Label(root, text="Sifra: ")
    password_label.pack()

    password = tk.Entry(root)
    password.pack()

    password_button = tk.Button(root, text="Generisi kljuceve", command=lambda:password_button_click(password.get(), private_key))
    password_button.pack(pady=20)

    return password

submit_button = tk.Button(root, text="Generisi kljuceve", command=generate_keys)
submit_button.pack(pady=20)



root.mainloop()
