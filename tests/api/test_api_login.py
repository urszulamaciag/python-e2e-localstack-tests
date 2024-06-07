import pytest
import os
from api.post_sign_in import SignIn
from dotenv import load_dotenv
import requests

load_dotenv()

@pytest.fixture
def sign_in_api():
    return SignIn()

def test_successful_api_login(sign_in_api: SignIn):
    response = sign_in_api.api_call(os.getenv("ADMIN_USERNAME"), os.getenv("ADMIN_PASSWORD"))
    try:
        response.raise_for_status()
        assert response.status_code == 200, "Expected status code 200"
        assert response.json()['token'] is not None, "Token should not be None"
    except requests.exceptions.HTTPError as e:
        pytest.fail(f"HTTPError occurred: {str(e)}")

def test_should_return_400_if_username_or_password_too_short(sign_in_api: SignIn):
    try:
        sign_in_api.api_call("one", "two")
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 400, "Expected status code 400"
        assert "username length" in e.response.json()["username"], "Username error should mention length"
        assert "password length" in e.response.json()["password"], "Password error should mention length"

def test_should_return_422_on_wrong_username(sign_in_api: SignIn):
    try:
        sign_in_api.api_call(os.getenv("ADMIN_USERNAME"), "wrong")
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 422, "Expected status code 422"
        assert "Invalid username/password supplied" == e.response.json()["message"], "Expected error message for wrong username"

def test_should_return_422_on_wrong_username(sign_in_api: SignIn):
    try:
        sign_in_api.api_call("wrong", os.getenv("ADMIN_PASSWORD"))
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 422, "Expected status code 422"
        assert "Invalid username/password supplied" == e.response.json()["message"], "Expected error message for wrong username"