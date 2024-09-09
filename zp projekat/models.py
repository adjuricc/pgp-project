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

    def get_email(self):
        return self.email

    def print_user(self):
        print(self.username, self.email, self.password, self.my_keys)


class PrivateKeyRing:
    def __init__(self, user_id):
        self.user_id = user_id
        self.user_keys = []

    def add_key(self, timestamp, key_id, public_key, private_key):
        self.user_keys.append({'timestamp': timestamp, 'key_id': key_id, 'public_key': public_key.public_numbers(), 'private_key': private_key})

    def get_user_id(self):
        return self.user_id

    def get_user_keys(self):
        return [list(key.values()) for key in self.user_keys]

    def print_ring(self):
        print("User: " + self.user_id)
        print("\n")
        print("Keys:\n")

        for key in self.user_keys:
            print(key["timestamp"], key["key_id"], key["public_key"], key["private_key"])
            print("\n")


class PublicKeyRing:
    def __init__(self, user_id):
        self.user_id = user_id
        self.keys = []

    def add_key(self, user_id, timestamp, key_id, public_key):
        print("??")
        self.keys.append({'user_id': user_id, 'timestamp': timestamp, 'key_id': key_id, 'public_key': public_key.public_numbers()})

    def get_user_keys(self):
        return [list(key.values()) for key in self.keys]

    def print_ring(self):
        print("User: " + self.user)
        print("\n")
        print("Keys:\n")

        for key in self.keys:
            print(key["user_id"], key["timestamp"], key["key_id"], key["public_key"])
            print("\n")


class Ivs:
    def __init__(self, user_id):
        self.user_id = user_id
        self.values = []

    def add_value(self, value):
        self.values.append(value)


class Message:
    def __init__(self, timestamp, filename, message):
        self.timestamp = timestamp
        self.filename = filename
        self.message = message
        self.signature = None
        self.public_key_id = None
        self.sender_id = None
