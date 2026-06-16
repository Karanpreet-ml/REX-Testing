from datetime import datetime, timedelta
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

        if user.locked_until and user.locked_until > datetime.utcnow():
            return {
                "success": False,
                "status": 423,
                "message": "Account locked"
            }

        if user.password != password:
            user.failed_attempts += 1

            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)

            self.repo.save(user)

            return {
                "success": False,
                "status": 401,
                "message": "Invalid credentials"
            }

        self.repo.save(user)

        return {
            "success": True,
            "status": 200,
            "message": "Login successful"
        }