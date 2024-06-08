## Project setup

You need to create .env file in the root of the project and fill it with the following variables:

```
FRONTEND_URL=http://localhost:8081
BACKEND_URL=http://localhost:4001
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
IS_HEADLESS=true
```

## Run in parallel

Warning: this mode disables test logs.

```
pytest tests/ -n 4
```


## Allure

The project should deploy allure report to github pages. The report is generated from sequentional test execution job.

To run allure report locally use the following command:

```
allure serve allure-results
```

