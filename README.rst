============================
Ubuntu Package BuilInfo
============================


.. image:: https://img.shields.io/pypi/v/ubuntu-package-buildinfo.svg
        :target: https://pypi.python.org/pypi/ubuntu-package-buildinfo

.. image:: https://img.shields.io/travis/canonical/ubuntu-package-buildinfo.svg
        :target: https://travis-ci.com/canonical/ubuntu-package-buildinfo

.. image:: https://readthedocs.org/projects/ubuntu-package-buildlog-info/badge/?version=latest
        :target: https://ubuntu-package-buildlog-info.readthedocs.io/en/latest/?version=latest
        :alt: Documentation Status




Tool to retrieve Ubuntu Package Buildinfo

This script downloads the changes file, the buildlog file and the buildinfo file and verifies
that the buildinfo file is correct based on the checksum in the .changes file.

See https://wiki.debian.org/ReproducibleBuilds/BuildinfoFiles for more information on buildinfo files.


* Free software: GNU General Public License v3
* Documentation: https://ubuntu-package-buildlog-info.readthedocs.io.

Example Usage
-------------

::

    ubuntu-package-buildinfo --series jammy --package-version 3.0.4-2ubuntu2.2 --package-name apparmor


Features
--------

Downloads the changes file, the buildlog file and the buildinfo file for a given package and version in a given
Ubuntu series.

It also verifies that the buildinfo file is correct based on the checksum in the .changes file.

TODO
----

* Code cleanup now that we have a working version
* Write tests
* Complete support for querying PPAs
* Add support for querying latest version of a package in a series if no version is specified
* Create snapcraft.yaml to build a snap package for easy distribution

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
