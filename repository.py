class User:
    def __init__(self, username):
        self.username = username


class UserRepository:
    def get_user(self, username):
        return User(username)