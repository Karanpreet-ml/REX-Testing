from repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    def get_profile(self, username):
        return self.repo.get_user(username)