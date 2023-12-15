import setuptools
import nhalqcli

setuptools.setup(
    name="dev.nhalq.cli",
    version=nhalqcli.__version__,
    description="Nha's Command Line Interface",
    author="nhalq",

    scripts=["bin/qx"],
    requires=[
        "PyYAML",
        "pyotp",
        "pycryptodome"
    ],
)
