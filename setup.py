from setuptools import setup, find_packages

setup(
    name="ceoassistant",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "flask",
        "flask-login",
        "flask-sqlalchemy",
        "google-api-python-client",
        "google-auth",
        "google-auth-oauthlib",
        "requests",
        "openai",
        "slack-sdk",
    ],
    python_requires=">=3.9",
)
