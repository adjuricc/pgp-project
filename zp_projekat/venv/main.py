import tkinter as tk
import rsa
import hashlib
import csv
import time
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

def update_private_key_ring(email, private_key, public_key, password):
    # public_key_bytes = rsa.key.PublicKey.save_pkcs1(public_key)
    der_public_key = public_key.save_pkcs1(format='DER')
    least_significant_8_bytes = der_public_key[-8:]

    with open('private_key_ring.csv', newline='\n') as csvfile:
        reader = csv.reader(csvfile)

        reader_lst = list(reader)

        found = False

        for i in range(1, len(reader_lst)):
            if reader_lst[i][4] == email:
                reader_lst[i][0] = time.time()
                reader_lst[i][1] = least_significant_8_bytes
                reader_lst[i][2] = public_key
                reader_lst[i][3] = private_key
                reader_lst[i][5] = password

                found = True

                break

    if found == False:
        print(type(email), email)
        new_row = [str(time.time()), str(least_significant_8_bytes), str(public_key), str(private_key), str(email), str(password)]
        reader_lst.append(new_row)

    with open('private_key_ring.csv', 'w', newline='\n') as file:
        writer = csv.writer(file)
        writer.writerows(reader_lst)

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

submit_button = tk.Button(root, text="Generisi kljuceve", command=generate_keys)
submit_button.pack(pady=20)



root.mainloop()
