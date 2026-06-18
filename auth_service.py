from datetime import datetime
from repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self.repo = repo