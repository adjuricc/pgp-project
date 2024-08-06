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


class PrivateKeyRing:
    def __init__(self, user_id):
        self.user_id = user_id
        self.user_keys = []

    def add_key_(self, timestamp, key_id, public_key, private_key):
        self.user_keys.append({'timestamp': timestamp, 'key_id': key_id, 'public_key': public_key, 'private_key': private_key})

    def print_ring(self):
        print("User: " + self.user_id)
        print("\n")
        print("Keys:\n")

        for key in self.user_keys:
            print(key.timestamp, key.key_id, key.public_key, key.private_key, key.user_id)
            print("\n")


class PublicKeyRing:
    def __init__(self, timestamp, key_id, public_key, user_id):
        self.timestamp = timestamp
        self.key_id = key_id
        self.public_key = public_key
        self.user_id = user_id
