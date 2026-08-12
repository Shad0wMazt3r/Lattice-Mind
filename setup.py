"""Setup configuration for lattice-mind."""
from setuptools import setup, find_packages

setup(
    name="lattice-mind",
    version="0.1.0",
    description="Autonomous CTF exploitation and vulnerability detection toolkit",
    author="Lattice Mind Team",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "lattice_mind": [
            "frontend/*.css",
            "frontend/*.html",
            "frontend/*.js",
            "trees/yaml/*.yaml",
            "trees/yaml/*/*.yaml",
        ],
    },
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.27.0",
        "requests>=2.31.0",
        "python-multipart>=0.0.9",
        "passlib[bcrypt]>=1.7.4",
        "bcrypt>=3.2.0,<4.0.0",
        "python-jose[cryptography]>=3.3.0",
        "PyYAML>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "httpx2>=2.0.0",
            "setuptools>=69",
            "wheel>=0.43",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.950",
        ],
    },
    entry_points={
        "console_scripts": [
            "Lattice-Mind=lattice_mind.cli:main",
            "Lattice-Mind-api=lattice_mind.api.server:main",
            "Lattice-Mind-mcp=lattice_mind.mcp.server:main",
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
