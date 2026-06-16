from datetime import datetime


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password


class UserRepository:
    def __init__(self):
        self.users = {}

    def get_by_username(self, username):
        return self.users.get(username)

    def save(self, user):
        self.users[user.username] = user