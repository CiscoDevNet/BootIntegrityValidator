from setuptools import setup, find_packages


requirements = ["pyOpenSSL ==20.0.1", "Pycrypto ==2.6.1", "cffi ==1.14.6", "setuptools"]

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
    packages=find_packages(),
    install_requires=requirements,
    test_requires=["pytest"],
    package_data={
        "BootIntegrityValidator": [
            "certs/*.cer",
            "certs/*.txt",
            "certs/*.pem",
            "yang/*.yang",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
    ],
    url=__homepage__,
)
