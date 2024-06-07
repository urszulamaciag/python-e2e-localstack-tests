from api.data.login import LoginRequestDto
from api.base_api import BaseAPI


class SignIn(BaseAPI):
    def api_call(self, username, password):
        login_request = LoginRequestDto(username=username, password=password).to_dict()
        response = self.make_request("POST", "users/signin", json=login_request)
        return response
