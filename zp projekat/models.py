import bcrypt

class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.my_keys = []

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password)

    def add_key_pair(self, private_key, public_key):
        self.my_keys.append({'private_key': private_key, 'public_key': public_key})

    def print_user(self):
        print(self.username, self.email, self.password, self.my_keys)