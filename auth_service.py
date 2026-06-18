from datetime import datetime
from repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    # logout renamed
    def sign_out(self, username: str):
        return {
            "success": True,
            "message": f"{username} signed out"
        }