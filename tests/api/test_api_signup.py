import pytest
from api.post_sign_up import SignUp
from generators.user_generator import get_random_user
import requests

@pytest.fixture
def sign_up_api():
    return SignUp()

def test_successful_api_signup(sign_up_api: SignUp):
    user = get_random_user()
    response = sign_up_api.api_call(user)
    try:
        response.raise_for_status()
        assert response.status_code == 201, "Expected status code 201"
        assert response.json()['token'] is not None, "Token should not be None"
    except requests.exceptions.HTTPError as e:
        pytest.fail(f"HTTPError occurred: {str(e)}")

def test_should_return_400_if_username_or_password_too_short(sign_up_api: SignUp):
    user = get_random_user()
    user.username = "usr"
    user.password = "pwd"
    try:
        sign_up_api.api_call(user)
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 400, "Expected status code 400"
        assert "username length" in e.response.json()["username"], "Username error should mention length"
        assert "password length" in e.response.json()["password"], "Password error should mention length"

def test_should_return_422_if_username_exists(sign_up_api: SignUp):
    user = get_random_user()
    sign_up_api.api_call(user)  # First call to create the user

    try:
        sign_up_api.api_call(user)  # Second call with the same user
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 422, "Expected status code 422"
        assert e.response.json()["error"], "Username is already in use"

def test_should_return_403_if_access_denied(sign_up_api: SignUp):
    user = get_random_user()
    user.token = "invalid_token"  # Simulate an invalid token or unauthorized access

    try:
        sign_up_api.api_call(user)
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 403, "Expected status code 403"
        assert e.response.json()["description"] == "Access denied", "Expected error message 'Access denied'"


def test_should_return_400_if_field_validation_failed(sign_up_api: SignUp):
    user = get_random_user()
    user.username = ""  # Simulate a validation error by providing an empty username
    user.email = "invalid_email"  # Simulate a validation error by providing an invalid email

    try:
        sign_up_api.api_call(user)
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 400, "Expected status code 400"
        response_json = e.response.json()
        assert response_json["email"] == "must be a well-formed email address", "Expected email validation error"
        assert response_json["username"] == "Minimum username length: 4 characters", "Expected username validation error"

def test_should_return_500_if_internal_server_error(sign_up_api: SignUp):
    user = get_random_user()
    user.username = "valid_username"
    user.email = "valid_email@example.com"

    try:
        sign_up_api.api_call(user)
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 500, "Expected status code 500"
        response_json = e.response.json()
        assert response_json["status"] == 500, "Expected status 500"
        assert response_json["error"] == "Internal Server Error", "Expected error 'Internal Server Error'"
        assert response_json["message"] == "Something went wrong", "Expected message 'Something went wrong'"
        assert response_json["path"] == "/users/signup", "Expected path '/users/signup'"