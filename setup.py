#!/usr/bin/env python3.9

import setuptools

with open("README.md", "r") as fp:
    long_description = fp.read()

setuptools.setup(
    name="synack-api",
    version="0.0.1",
    author="mhnrv",
    author_email="hello@binarysouljour.me",
    description="A package to interact with Synack's API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://www.github.com/mhnrv/mapi",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"
    ],
    python_requires=">=3.6",
    packages=['synack', 'synack.plugins', 'synack.db'],
    package_data={
        'synack.db': ['alembic.ini', 'alembic/*', 'alembic/**/*', 'models/*'],
    },
    package_dir={'': 'src'},
    install_requires=[
        "alembic==1.8.1",
        "netaddr==0.8.0",
        "pathlib2==2.3.6",
        "psycopg2-binary==2.9.5",
        "pyaml==21.10.1",
        "pyotp==2.7.0",
        "requests==2.28.1",
        "SQLAlchemy==1.4.44",
        "urllib3",
        "requests",
        "bs4",
        "pycryptodome",
    ]
)
