from distutils.core import setup

# Pull the install_requires from the requirement.txt
with open("requirements.txt") as f:
    original_lines = f.readlines()
    requirements = []
    for module in original_lines:
        if not module.startswith("#"):
            requirements.append(module.strip())

# Load the package meta data per #3
# https://packaging.python.org/single_source_version/#single-sourcing-the-version
exec(open('BootIntegrityValidator/package_meta_data.py').read())

setup(name=__title__,
      version=__version__,
      description=__description__,
      author=__author__,
      author_email=__author_email__,
      packages=['BootIntegrityValidator'],
      install_requires=requirements,
      package_data={'BootIntegrityValidator': ['certs/*.cer', 'certs/*.txt', 'certs/*.pem']}
)
