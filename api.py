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

login_result = service.login(
    "john",
    "secret"
)

print(login_result)

is_valid = service.validate_credentials(
    "john",
    "secret"
)

print(is_valid)

print(
    service.health_check()
)