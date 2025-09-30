from setuptools import setup, find_packages

setup(
    name="malyz3r",
    version="1.0.0",
    description="Advanced, user-friendly malware scanner CLI with YARA integration",
    author="gl1tch0x1",
    packages=find_packages(),
    install_requires=[
        "colorama",
        "python-magic",
        "requests",
        "yara-python",
        "psutil"
    ],
    entry_points={
        "console_scripts": [
            "malyz3r=malware_scanner.cli:run"
        ]
    },
    include_package_data=True,
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
