from setuptools import setup
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="emergency_git_server",
    author="Jane Soko",
    author_email="boynamedjane@misled.ml",
    version="0.0.2",
    url="https://github.com/poppyschmo/emergency-git-server",
    description="A minimal Git HTTP server",
    long_description=long_description,
    license="Apache 2.0",
    keywords="backend development education git http server simple ssl tls",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development :: Version Control :: Git"
    ],
    install_requires=[],
    packages=[],
    py_modules=["emergency_git_server"],
    python_requires=", ".join([">=2.7"] + ["!=3.%d.*" % d for d in range(4)]),
    entry_points={
        "console_scripts": ["emergency-git-server = emergency_git_server:main"]
    }
)
