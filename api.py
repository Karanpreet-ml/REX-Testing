from repository import UserRepository, User
from auth_service import AuthService

repo = UserRepository()

repo.save(
    User(
        username="john",
        password="secret"
    )
)

service = AuthService(repo)

print(
    service.get_profile("john")
)

print(
    service.health_check()
)

print("Login attempt with correct credentials:")