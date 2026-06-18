from repository import UserRepository
from auth_service import AuthService


repo = UserRepository()
service = AuthService(repo)

profile = service.get_profile("john")
print(profile.username)

name = service.get_profile_name("john")
print(name)