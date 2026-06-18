from datetime import datetime
from repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    def login(self, username: str, password: str):
        user = self.repo.get_by_username(username)

        if user is None:
            return {
                "success": False,
                "status": 401,
                "message": "Invalid credentials"
            }

        if user.password != password:
            return {
                "success": False,
                "status": 401,
                "message": "Invalid credentials"
            }

        return {
            "success": True,
            "status": 200,
            "message": "Login successful"
        }

    def authenticate_user(self, username: str, password: str):
        user = self.repo.get_by_username(username)

        if user is None:
            return False

        return user.password == password