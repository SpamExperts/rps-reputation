#! /usr/bin/env python

from __future__ import absolute_import

import yaml
import distutils.core


with open('manifest.yml', 'r') as f:
    version = yaml.safe_load(f).get('version')

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

distutils.core.setup(
    name='rps-reputation',
    description=DESCRIPTION,
    author="SpamExperts",
    version=version,
    license='GPL',
    platforms='POSIX',
    keywords='spam',
    classifiers=CLASSIFIERS,
    # scripts=[],
    requires=REQUIRES,
    packages=[
        'rps',
    ],
)
