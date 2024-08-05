import tkinter as tk

class AppGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PGP")
        self.root.geometry("600x700")

        # Initializing navbar
        self.navbar = tk.Frame(root, bg="lightblue", height=50)
        self.navbar.pack(side=tk.TOP, fill=tk.X)

        self.register_button = tk.Button(self.navbar, text="Register")
        self.register_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.login_button = tk.Button(self.navbar, text="Login")
        self.login_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.generate_key_pair_button = tk.Button(self.navbar, text="Generate key pair")
        self.generate_key_pair_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.send_msg_button = tk.Button(self.navbar, text="Send message")
        self.send_msg_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.receive_msg_button = tk.Button(self.navbar, text="Receive message")
        self.receive_msg_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.import_keys_button = tk.Button(self.navbar, text="Import keys")
        self.import_keys_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.export_keys_button = tk.Button(self.navbar, text="Export keys")
        self.export_keys_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Initializing main frame
        self.main = tk.Frame(root)
        self.main.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Initializing footer
        self.footer = tk.Frame(root, bg="lightblue", height=50)
        self.footer.pack(side=tk.BOTTOM, fill=tk.X)

        self.log_out_button = tk.Button(self.footer, text="Log out")
        self.log_out_button.grid(row=0, column=1, padx=5, pady=5)

        self.status = tk.Label(self.footer, text="", fg="red", bg="lightblue")
        self.status.grid(row=0, column=0, padx=5, pady=15, sticky=tk.W)

        self.footer.grid_columnconfigure(0, weight=1)  # Status label column
        self.footer.grid_columnconfigure(1, weight=0)  # Log out button column

        self.register_action_button = None
        self.login_action_button = None
        self.generate_keys_action_button = None

        self.register_action_callback = None
        self.login_action_callback = None
        self.generate_key_pair_action_callback = None

    def set_status(self, message):
        self.status.config(text=message)
        self.status.update_idletasks()

    def clear_main(self):
        for widget in self.main.winfo_children():
            widget.destroy()

        for i in range(self.main.grid_size()[0]):
            self.main.grid_columnconfigure(i, weight=0)
        for i in range(self.main.grid_size()[1]):
            self.main.grid_rowconfigure(i, weight=0)

    def set_navbar_commands(self, commands):
        self.register_button.config(command=commands['register'])
        self.login_button.config(command=commands['login'])
        self.generate_key_pair_button.config(command=commands['generate_key_pair'])
        self.send_msg_button.config(command=commands['send_msg'])
        self.receive_msg_button.config(command=commands['receive_msg'])
        self.import_keys_button.config(command=commands['import_keys'])
        self.export_keys_button.config(command=commands['export_keys'])

    def set_footer_commands(self, commands):
        self.log_out_button.config(command=commands['log_out'])

    def set_register_action(self, callback):
        self.register_action_callback = callback

    def handle_register(self):
        username = self.username_input.get()
        email = self.email_input.get()
        password = self.password_input.get()
        if self.register_action_callback:
            self.register_action_callback(username, email, password)

    def register_page(self):
        self.clear_main()
        self.main.grid_propagate(False)

        self.main.grid_columnconfigure(0, weight=1)  # Empty space on the left
        self.main.grid_columnconfigure(1, weight=0)  # Content column (labels)
        self.main.grid_columnconfigure(2, weight=0)  # Content column (entries)
        self.main.grid_columnconfigure(3, weight=1)  # Empty space on the right

        self.main.grid_rowconfigure(0, weight=1)  # Empty space at the top
        self.main.grid_rowconfigure(1, weight=0)  # Username row
        self.main.grid_rowconfigure(2, weight=0)  # Email row
        self.main.grid_rowconfigure(3, weight=0)  # Password row
        self.main.grid_rowconfigure(4, weight=0)  # Register button row
        self.main.grid_rowconfigure(5, weight=1)  # Empty space at the bottom
        # Username input
        self.username_label = tk.Label(self.main, text="Username:")
        self.username_label.grid(row=1, column=0, padx=5, pady=15, sticky=tk.E)
        self.username_input = tk.Entry(self.main)
        self.username_input.grid(row=1, column=1, padx=5, pady=15, sticky=tk.W)

        # Email input
        self.email_label = tk.Label(self.main, text="Email:")
        self.email_label.grid(row=2, column=0, padx=5, pady=15, sticky=tk.E)
        self.email_input = tk.Entry(self.main)
        self.email_input.grid(row=2, column=1, padx=5, pady=15, sticky=tk.W)

        # Password input
        self.password_label = tk.Label(self.main, text="Password:")
        self.password_label.grid(row=3, column=0, padx=5, pady=15, sticky=tk.E)
        self.password_input = tk.Entry(self.main, show="*")
        self.password_input.grid(row=3, column=1, padx=5, pady=15, sticky=tk.W)

        # Register button
        self.register_action_button = tk.Button(self.main, text="Register", command=self.handle_register)
        self.register_action_button.grid(row=4, column=1, padx=10, pady=15, sticky=tk.W)
        # main.on_register()
        
    def set_login_action(self, callback):
        self.login_action_callback = callback

    def handle_login(self):
        username = self.username_input_login.get()
        password = self.password_input_login.get()
        if self.login_action_callback:
            self.login_action_callback(username, password)

    def login_page(self):
        self.clear_main()
        self.main.grid_propagate(False)

        # Configuring the columns and rows for centering
        self.main.grid_columnconfigure(0, weight=1)  # Empty space on the left
        self.main.grid_columnconfigure(1, weight=0)  # Content column (labels)
        self.main.grid_columnconfigure(2, weight=0)  # Content column (entries)
        self.main.grid_columnconfigure(3, weight=1)  # Empty space on the right

        self.main.grid_rowconfigure(0, weight=1)  # Empty space at the top
        self.main.grid_rowconfigure(1, weight=0)  # Username row
        self.main.grid_rowconfigure(2, weight=0)  # Password row
        self.main.grid_rowconfigure(3, weight=0)  # Login button row
        self.main.grid_rowconfigure(4, weight=1)  # Empty space at the bottom

        # Username input
        self.username_label_login = tk.Label(self.main, text="Username:")
        self.username_label_login.grid(row=1, column=1, padx=5, pady=15, sticky=tk.E)
        self.username_input_login = tk.Entry(self.main)
        self.username_input_login.grid(row=1, column=2, padx=5, pady=15, sticky=tk.W)

        # Password input
        self.password_label_login = tk.Label(self.main, text="Password:")
        self.password_label_login.grid(row=2, column=1, padx=5, pady=15, sticky=tk.E)
        self.password_input_login = tk.Entry(self.main, show="*")
        self.password_input_login.grid(row=2, column=2, padx=5, pady=15, sticky=tk.W)

        # Login button
        self.login_action_button = tk.Button(self.main, text="Login", command=self.handle_login)
        self.login_action_button.grid(row=3, column=2, padx=10, pady=15, sticky=tk.W)

    def set_generate_key_pair_action(self, callback):
        self.generate_key_pair_action_callback = callback

    def handle_generate_key_pair(self):
        key_size = int(self.key_size_var.get())
        if self.generate_key_pair_action_callback:
            self.generate_key_pair_action_callback(key_size)

    def generate_key_pair_page(self):
        self.clear_main()

        self.key_size_label = tk.Label(self.main, text="Key size:")
        self.key_size_label.grid(row=2, column=1, padx=5, pady=15, sticky=tk.E)

        self.key_size_var = tk.StringVar()
        self.key_size_var.set("1024")  # Set default value

        self.val_1024_radio = tk.Radiobutton(self.main, text="1024", variable=self.key_size_var, value="1024")
        self.val_1024_radio.grid(row=3, column=2, padx=5, pady=5, sticky=tk.W)

        self.val_2048_radio = tk.Radiobutton(self.main, text="2048", variable=self.key_size_var, value="2048")
        self.val_2048_radio.grid(row=3, column=3, padx=5, pady=5, sticky=tk.E)

        self.generate_keys_action_button = tk.Button(self.main, text="Generate", command=self.handle_generate_key_pair)
        self.generate_keys_action_button.grid(row=6, column=2, padx=10, pady=15, sticky=tk.W)

    def send_message_page(self):
        print("send page")

    def receive_message_page(self):
        print("receive page")

    def import_keys_page(self):
        print("import page")

    def export_keys_page(self):
        print("export page")

if __name__ == '__main__':
    print("Can't run this file. Try main.py")