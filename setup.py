import nhalqcli
import setuptools


setuptools.setup(
    name='dev.nhalq.cli',
    version=nhalqcli.__version__,
    description='Nha\'s personal CLI',
    author='Nha Q. Le',
    url='https://cli.nhalq.dev',

    scripts=['bin/nhalq', 'bin/nhalq_complete.zsh'],
    requires=['PyYAML', 'pyotp', 'pycryptodome']
)
