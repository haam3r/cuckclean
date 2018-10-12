from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='cuckclean',
    version='0.7',
    author="haam3r",
    description="CLI utility to operate MongoDB documents of Cuckoo Sandbox",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/haam3r/cuckclean",
    py_modules=['cuckclean'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'Click==6.6',
        'pymongo==3.0.3',
    ],
    entry_points='''
        [console_scripts]
        cuckclean=cuckclean:cli
    ''',
)
