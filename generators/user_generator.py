from faker import Faker

from api.data.register import User

faker = Faker()

def generate_attribute(attribute_generator, min_length: int) -> str:
    result = attribute_generator()
    attempts = 0
    while len(result) < min_length and attempts < 10:
        result = attribute_generator()
        attempts += 1
    return result

def generate_username() -> str:
    return generate_attribute(faker.user_name, 4)

def generate_password() -> str:
    return generate_attribute(faker.password, 4)

def generate_first_name() -> str:
    return generate_attribute(faker.first_name, 4)

def generate_last_name() -> str:
    return generate_attribute(faker.last_name, 4)

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
    firstName = generate_first_name()
    lastName = generate_last_name()

    return User(
        username=username,
        password=password,
        email=faker.email(),
        firstName=firstName,
        lastName=lastName,
        roles=["ROLE_ADMIN", "ROLE_CLIENT"],
    )