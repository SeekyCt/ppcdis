from setuptools import setup

setup(
    name='ppcdis',
    author="Seeky",
    classifiers=[
        "License :: OSI Approved :: MIT License"
    ],
    packages=["ppcdis"],
    python_requires=">=3.8",
    install_requires=[
        'colorama',
        'capstone==5.0.1',
        'pyelftools',
        'pylibyaml',
        'PyYAML'
    ],
)
