import setuptools
import io
import os


package_root = os.path.abspath(os.path.dirname(__file__))

readme_filename = os.path.join(package_root, 'README.md')
with io.open(readme_filename, encoding='utf-8') as readme_file:
    readme = readme_file.read()


setuptools.setup(
    name="python_pqc_wrapping",
    version="0.0.11",
    author="Sal Rashid",
    author_email="salrashid123@gmail.com",
    description="AEAD encryption using Post Quantum Cryptography (ML-KEM)",
    long_description=readme,
    long_description_content_type='text/markdown',
    url="https://github.com/salrashid123/python_pqc_wrapping",
    install_requires=[
        'pem',
        'asn1tools',
        'cryptography',
        'protobuf',
        'liboqs-python',
        # 'liboqs-python @ git+https://github.com/open-quantum-safe/liboqs-python.git'
    ],
    extras_require={
        'gcp': ['google-auth>=2.34.0'],     
    },    
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',

        "Programming Language :: Python",
        "Programming Language :: Python :: 3.0",

        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
