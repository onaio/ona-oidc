"""
Setup file for ona-oicd
"""
from setuptools import find_packages, setup

setup(
    name="ona-oicd",
    version=__import__("oicd").__version__,
    description="A Django app that adds OpenID connect client functionality.",
    license="",
    author="Ona Kenya",
    url="",
    packages=find_packages(exclude=[]),
    install_requires=[
        "Django >= 2.2",
        "djangorestframework >= 3.9",
        "pyjwt[crypto]",
        "requests"
    ],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Framework :: Django",
        "Framework :: Django :: 2.2",
        "Framework :: Django :: 3.0"
    ]
)
