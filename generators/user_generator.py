from faker import Faker

from api.data.register import User

fake = Faker()

def generate_username() -> str:
    username = fake.user_name()
    attempts = 0
    while len(username) < 4 and attempts < 10:
        username = fake.user_name()
        attempts += 1
    return username

def generate_password() -> str:
    password = fake.password()
    attempts = 0
    while len(password) < 4 and attempts < 10:
        password = fake.password()
        attempts += 1
    return password

def get_random_user() -> User:
    username = generate_username()
    password = generate_password()

    return User(
        username=username,
        password=password,
        email=fake.email(),
        firstName=fake.first_name(),
        lastName=fake.last_name(),
        roles=["ROLE_ADMIN", "ROLE_CLIENT"],
    )