"""Setup configuration for ctf-autopwn."""
from setuptools import setup, find_packages

setup(
    name="ctf-autopwn",
    version="0.1.0",
    description="Autonomous CTF exploitation and vulnerability detection toolkit",
    author="CTF Autopwn Team",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.27.0",
        "requests>=2.31.0",
        "python-multipart>=0.0.9",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.950",
        ],
    },
    entry_points={
        "console_scripts": [
            "ctf-autopwn=ctf_autopwn.cli:main",
            "ctf-autopwn-api=ctf_autopwn.api.server:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
)
