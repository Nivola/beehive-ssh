#!/usr/bin/env python
# SPDX-License-Identifier: EUPL-1.2
#
# (C) Copyright 2018-2024 CSI-Piemonte

from sys import version_info
from setuptools import setup
from setuptools.command.install import install as _install


class install(_install):
    def pre_install_script(self):
        pass

    def post_install_script(self):
        pass

    def run(self):
        self.pre_install_script()

        _install.run(self)

        self.post_install_script()


def load_requires():
    with open("./MANIFEST.md") as f:
        requires = f.read()
    return requires


def load_version():
    with open("./beehive_ssh/VERSION") as f:
        version = f.read()
    return version


if __name__ == "__main__":
    version = load_version()
    setup(
        name="beehive_ssh",
        version=version,
        description="Nivola server connection manager package",
        long_description="Nivola server connection manager package",
        author="CSI Piemonte",
        author_email="nivola.engineering@csi.it",
        license="EUPL-1.2",
        url="",
        scripts=[],
        packages=[
            "beehive_ssh",
            "beehive_ssh.dao",
            "beehive_ssh.tests",
            "beehive_ssh.views",
        ],
        namespace_packages=[],
        py_modules=[
            "beehive_ssh.controller",
            "beehive_ssh.event",
            "beehive_ssh.__init__",
            "beehive_ssh.model",
            "beehive_ssh.mod",
        ],
        classifiers=[
            "Development Status :: %s" % version,
            "Programming Language :: Python",
        ],
        entry_points={},
        data_files=[],
        package_data={"beehive_ssh": ["VERSION"]},
        install_requires=load_requires(),
        dependency_links=[],
        zip_safe=True,
        cmdclass={"install": install},
        keywords="",
        python_requires="",
        obsoletes=[],
    )
