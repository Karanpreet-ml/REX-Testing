from datetime import datetime
from repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    def audit_log(self, event, username):
        print(f"AUDIT: {event} {username}")

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

        if not user.is_email_verified:
            self.audit_log("UNVERIFIED_LOGIN_BLOCKED", username)

            return {
                "success": False,
                "status": 403,
                "message": "Email verification required"
            }

        if user.password != password:
            user.failed_attempts += 1

            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow()
                self.audit_log("ACCOUNT_LOCKED", username)

            self.repo.save(user)

            return {
                "success": False,
                "status": 401,
                "message": "Invalid credentials"
            }

        user.failed_attempts = 0
        user.locked_until = None

        self.audit_log("ACCOUNT_UNLOCKED", username)

        self.repo.save(user)

        return {
            "success": True,
            "status": 200,
            "message": "Login successful"
        }