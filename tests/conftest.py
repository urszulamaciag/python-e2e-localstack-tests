import json
import pytest
import os
from selenium import webdriver
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from api import delete_user

from api.post_sign_in import SignIn
from api.delete_user import DeleteUser
from api.post_sign_up import SignUp
from generators.user_generator import get_random_user
from pages.home_page import HomePage
from dotenv import load_dotenv

load_dotenv()
frontend_url = os.getenv("FRONTEND_URL")


@pytest.fixture
def chrome_browser():
    options = Options()
    if os.getenv("IS_HEADLESS") == "true":
        options.add_argument("--headless")
    service = Service(ChromeDriverManager().install())
    browser = Chrome(service=service, options=options)
    yield browser
    browser.quit()


@pytest.fixture
def logged_in_test(chrome_browser: webdriver):
    user = setup_test_user()
    login_response = login_test_user(chrome_browser, user)
    setup_user_local_storage(chrome_browser, login_response)
    chrome_browser.get(frontend_url)
    yield HomePage(chrome_browser), login_response["token"], user
    DeleteUser().api_call(user.username, login_response["token"])


def setup_test_user():
    user = get_random_user()
    register_response = SignUp().api_call(user)
    assert register_response.status_code == 201, "Failed to register"
    return user


def login_test_user(browser, user):
    browser.get(frontend_url)
    login_response = SignIn().api_call(user.username, user.password)
    return login_response.json()


def cleanup_test_user(user, token):
    delete_user(user.username, token)


def setup_user_local_storage(browser, login_response):
    browser.execute_script(
        "window.localStorage.setItem(arguments[0], arguments[1])",
        "user",
        json.dumps(login_response),
    )
