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

print(service.login("john", "secret"))
print(service.logout("john"))