#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['Click>=7.0', 'launchpadlib']

test_requirements = [ ]

setup(
    author="Phil Roche",
    author_email='phil.roche@canonical.com',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="Tool to retrieve Ubuntu Package Buildinfo",
    entry_points={
        'console_scripts': [
            'ubuntu-package-buildinfo=ubuntu_package_buildinfo.cli:ubuntu_package_buildinfo',
        ],
    },
    install_requires=requirements,
    license="GNU General Public License v3",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='ubuntu-package-buildinfo',
    name='ubuntu-package-buildinfo',
    packages=find_packages(include=['ubuntu_package_buildinfo', 'ubuntu_package_buildinfo.*']),
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/canonical/ubuntu-package-buildinfo',
    version='0.0.9',
    zip_safe=False,
)
