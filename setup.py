from setuptools import setup

setup(
    name='ppcdis',
    version='1.0.0',
    author="Seeky",
    classifiers=[
        "License :: OSI Approved :: MIT License"
    ],
    packages=["ppcdis"],
    python_requires=">=3.8",
    install_requires=[
        'colorama',
        'capstone',
        'pyelftools',
        'pylibyaml',
        'PyYAML'
    ],
    entry_points={
        'console_scripts': [
            'relextern = relextern.py'
        ]
    }
)
