from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded.
        import pytest
        import sys
        import os

        os.chdir("tests")
        errno = pytest.main(["-v", "-x"])
        sys.exit(errno)


requirements = ["pyOpenSSL ==20.0.1", "Pycrypto ==2.6.1", "cffi ==1.14.6","setuptools"]

# Load the package meta data per #3
# https://packaging.python.org/single_source_version/#single-sourcing-the-version
exec(open("BootIntegrityValidator/package_meta_data.py").read())

setup(
    name=__title__,
    version=__version__,
    description=__description__,
    long_description=__long_description__,
    author=__author__,
    author_email=__author_email__,
    packages=["BootIntegrityValidator"],
    install_requires=requirements,
    test_requires=["pytest"],
    cmdclass={"test": PyTest},
    package_data={
        "BootIntegrityValidator": ["certs/*.cer", "certs/*.txt", "certs/*.pem"]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
    ],
    url=__homepage__,
)
