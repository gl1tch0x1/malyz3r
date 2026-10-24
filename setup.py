from setuptools import find_packages, setup

setup(
    name="malyz3r",
    version="1.0.0",
    description="Advanced, user-friendly malware scanner CLI with YARA integration",
    author="gl1tch0x1",
    packages=find_packages(include=["malware_scanner", "malware_scanner.*"]),
    install_requires=["colorama", "python-magic", "requests", "yara-python>=4.3,<5", "psutil"],
    extras_require={"dev": ["ruff==0.15.9"], "mcp": ["mcp==2.3.0; python_version >= '3.11'"]},
    entry_points={
        "console_scripts": [
            "malyz3r=malware_scanner.cli:run",
            "malyz3r-lab=malware_scanner.lab:main",
            "malyz3r-workbench=malware_scanner.workbench:main",
            "malyz3r-assist=malware_scanner.assistant:main",
            "malyz3r-mcp=malware_scanner.mcp_server:main",
        ]
    },
    include_package_data=True,
    package_data={"malware_scanner": ["rules/*.yar"]},
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
