import setuptools

# from src.aio_dtls import __version__

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name='aio_dtls',
    version='0.0.3',  # __version__,
    test_requires=[],
    url='https://github.com/businka/aio_dtls',
    license='MIT',
    author='Razgovorov Mikhail',
    author_email='1338833@gmail.com',
    description='asyncio implementation of the dtls protocol in python',
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Natural Language :: Russian',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development',
        "Operating System :: OS Independent"
    ],
    keywords='python tls dtls mbed asyncio',
    python_requires='>=3.9',
    zip_safe=False,
    install_requires=[
        "construct",
        "cryptography",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src")
)
