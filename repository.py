class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.is_email_verified = False