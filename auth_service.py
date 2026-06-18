from datetime import datetime
from repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    def login(self, username: str, password: str):
        user = self.repo.get_by_username(username)

        if user is None:
            return False

        return user.password == password

    def logout(self, username: str):
        return {
            "success": True,
            "message": f"{username} logged out"
        }