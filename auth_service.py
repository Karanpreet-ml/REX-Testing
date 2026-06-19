from repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    def login(self, username: str, password: str):
        user = self.repo.get_by_username(username)

        if user is None:
            return {
                "success": False,
                "message": "Invalid credentials"
            }

        if user.password != password:
            return {
                "success": False,
                "message": "Invalid credentials"
            }

        return {
            "success": True,
            "message": "Login successful"
        }

    def validate_credentials(self, username: str, password: str):
        user = self.repo.get_by_username(username)

        if user is None:
            return False

        return user.password == password

    def health_check(self):
        return {
            "service": "auth",
            "status": "ok"
        }