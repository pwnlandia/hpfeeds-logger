#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

import os
import sys

try:
    import subprocess
    has_subprocess = True
except:
    has_subprocess = False

try:
    from ez_setup import use_setuptools
    use_setuptools()
except ImportError:
    pass

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from distutils.cmd import Command

long_description = """A library for consuming messages from hpfeeds honeypots and normalizing them"""

setup(
    name='hpfeeds-logger',
    version='0.0.7.7',
    author='Jason Trost',
    author_email='tech@threatstream.com',
    maintainer='Anomali, Inc.',
    maintainer_email='tech@threatstream.com',
    license='License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
    description='Python library to normalize and log hpfeeds honeypot messages',
    long_description=long_description,
    url='https://github.com/threatstream/hpfeeds-logger',
    keywords='hpfeeds logger normalizer formatter honeypots',
    packages=['hpfeedslogger',
        'hpfeedslogger.formatters',
        'hpfeedslogger'
    ],
    scripts=['bin/hpfeeds-logger'],
    install_requires=[
        'hpfeeds-threatstream==1.1',
        'geoip2==2.9.0'
    ],
    tests_require=[],
    py_modules=['ez_setup'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Software Development :: Libraries :: Python Modules'
        ],
)
