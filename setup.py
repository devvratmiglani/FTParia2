from setuptools import setup

setup(
    name="aria2ftp",
    version="1.0",
    description="",
    url="https://github.com/devvratmiglani",
    author="Devvrat Miglani",
    author_email="devvratmiglani@gmail.com",
    license="GNU VERSION 2",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ],
    packages=["client"],
    install_requires=[
        "setuptools>=64.0.0,<=69.0.2"
    ],
    entry_points="""
        [console_scripts]
        aftp=client:main
    """,
)