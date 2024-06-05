from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class AlertComponent:
    alert_success = (By.CLASS_NAME, "alert-success")
    alert_danger = (By.CLASS_NAME, "alert-danger")

    def __init__(self, driver):
        self.driver = driver
        self.wait = WebDriverWait(driver, 10)

    def verify_alert_success(self, expected_message: str):
        self.wait.until(EC.visibility_of_element_located(self.alert_success))
        actual_message = self.driver.find_element(*self.alert_success).text
        assert (
            expected_message in actual_message
        ), f"Expected message to be '{expected_message}' but found '{actual_message}'"

    def verify_alert_danger(self, expected_message: str):
        self.wait.until(EC.visibility_of_element_located(self.alert_danger))
        actual_message = self.driver.find_element(*self.alert_danger).text
        assert (
            expected_message in actual_message
        ), f"Expected message to be '{expected_message}' but found '{actual_message}'"

