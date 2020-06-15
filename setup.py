"""
Setup file for ona-oidc
"""
from setuptools import find_packages, setup

setup(
    name="ona-oidc",
    version=__import__("oidc").__version__,
    description="A Django app that adds OpenID connect client functionality.",
    license="",
    author="Ona Kenya",
    url="",
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        "Django >= 2.2",
        "djangorestframework >= 3.9",
        "pyjwt[crypto]",
        "requests",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Framework :: Django",
        "Framework :: Django :: 2.2",
        "Framework :: Django :: 3.0",
    ],
)
