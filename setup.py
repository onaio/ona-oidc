"""
Setup file for ona-oidc
"""
from setuptools import find_packages, setup

setup(
    name="ona-oidc",
    version=__import__("oidc").__version__,
    description="A Django app that adds OpenID connect client functionality.",
    license="Apache-2.0 License",
    author="Ona Kenya",
    url="https://github.com/onaio/ona-oidc",
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        "Django>=3.2.13,<4",
        "djangorestframework",
        "pyjwt[crypto]",
        "requests",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Framework :: Django",
        "Framework :: Django :: 3.2.13",
    ],
)
