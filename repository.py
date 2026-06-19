from datetime import datetime, timedelta


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.failed_attempts = 0
        self.locked_until = None


class UserRepository:
    def __init__(self):
        self.users = {}

    def get_by_username(self, username):
        return self.users.get(username)

    def save(self, user):
        self.users[user.username] = user