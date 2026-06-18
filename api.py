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

result = service.login("john", "secret")
print(result)

new_result = service.authenticate_user("john", "secret")
print(new_result)