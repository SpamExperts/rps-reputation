#! /usr/bin/env python

from __future__ import absolute_import

import rps
from setuptools import setup


REQUIRES = ["ipaddr"]
DESCRIPTION = """An implementation of the Roaring Penguin IP reputation
 reporting system."""

CLASSIFIERS = [
    "Operating System :: POSIX",
    "Programming Language :: Python",
    "Intended Audience :: System Administrators",
    "Topic :: Communications :: Email",
    "Topic :: Communications :: Email :: Filters",
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
]

setup(
    name='rps-reputation',
    description=DESCRIPTION,
    author="SpamExperts",
    version=rps.__version__,
    license='GPL',
    platforms='POSIX',
    keywords='spam',
    classifiers=CLASSIFIERS,
    # scripts=[],
    requires=REQUIRES,
    packages=[
        'rps',
    ],
    package_data={'rps': ['manifest.yml']},
)
