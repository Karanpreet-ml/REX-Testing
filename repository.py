from datetime import datetime


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.created_at = datetime.utcnow()


class UserRepository:
    def __init__(self):
        self.users = {}

    def save(self, user):
        self.users[user.username] = user

    def get_by_username(self, username):
        return self.users.get(username)

    def exists(self, username):
        return username in self.users

    def count(self):
        total = 0

        for _ in self.users:
            total += 1

        return total