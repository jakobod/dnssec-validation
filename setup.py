#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

import io
import re
from glob import glob
from os.path import basename
from os.path import dirname
from os.path import join
from os.path import splitext

from setuptools import find_packages
from setuptools import setup


def read(*names, **kwargs):
    return io.open(
        join(dirname(__file__), *names), encoding=kwargs.get("encoding", "utf8")
    ).read()


setup(
    name="dnssec",
    version="0.1.0",
    license="BSD 3-Clause License",
    description="",
    # long_description="%s\n%s"
    # % (
    #     re.compile("^.. start-badges.*^.. end-badges", re.M | re.S).sub(
    #         "", read("README.md")
    #     ),
    #     re.sub(":[a-z]+:`~?(.*?)`", r"``\1``", read("CHANGELOG.rst")),
    # ),
    author="",
    author_email="",
    url="",
    packages=find_packages("src"),
    package_dir={"": "src"},
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        # "Development Status :: 5 - Production/Stable",
        # "Intended Audience :: Developers",
        # "License :: OSI Approved :: BSD License",
        # "Operating System :: Unix",
        # "Operating System :: POSIX",
        # # 'Operating System :: Microsoft :: Windows',
        # "Programming Language :: Python",
        # # 'Programming Language :: Python :: 2.7',
        # "Programming Language :: Python :: 3",
        # # 'Programming Language :: Python :: 3.4',
        # # 'Programming Language :: Python :: 3.5',
        # "Programming Language :: Python :: 3.6",
        # "Programming Language :: Python :: 3.7",
        # "Programming Language :: Python :: Implementation :: CPython",
        # "Programming Language :: Python :: Implementation :: PyPy",
        # # uncomment if you test on these interpreters:
        # # 'Programming Language :: Python :: Implementation :: IronPython',
        # # 'Programming Language :: Python :: Implementation :: Jython',
        # # 'Programming Language :: Python :: Implementation :: Stackless',
        # "Topic :: Utilities",
    ],
    keywords=[
        # eg: 'keyword1', 'keyword2', 'keyword3',
    ],
    install_requires=[
        "certifi",
        "cffi",
        "chardet",
        "cryptography",
        "dnspython",
        "filelock",
        "idna",
        "numpy",
        "pandas",
        "pycparser",
        "python-dateutil",
        "pytz",
        "requests",
        "requests-file",
        "six",
        "tldextract",
        "tqdm",
        "urllib3",
        "seaborn",
        "ordered-enum"
    ],
    extras_require={
        # eg:
        #   'rst': ['docutils>=0.11'],
        #   ':python_version=="2.6"': ['argparse'],
    },
    entry_points={
        "console_scripts": [
            "probing = dnssec.probing.dnssec:main",
            "plot = dnssec.evaluation.plot:main",
            "evaluation = dnssec.evaluation.evaluation:main",

        ]
    },
)
