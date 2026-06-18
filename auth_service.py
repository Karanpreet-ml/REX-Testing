from repository import UserRepository


class AuthService:
    def __init__(self, repo: UserRepository):
        self.repo = repo

    def get_profile(self, username):
        return self.repo.get_user(username)

    def get_profile_name(self, username):
        user = self.repo.get_user(username)
        return user.username