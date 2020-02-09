#!/usr/bin/env python

import setuptools
from encryptedchatbot import version

current_version = version.bot_version()

setuptools.setup(

    name='encryptedchatbot',

    version=current_version,

    license='GPL-3.0',

    author='Adekaude Callie',
    author_email='not-show@gmail.com',

    install_requires=[
        'python-telegram-bot',
        'Pyyaml',
        'PyMySQL',
        'pynacl'
    ],

    packages=[
        'encryptedchatbot',
    ],

    entry_points={
        'console_scripts': [
            'encryptedchatbot = encryptedchatbot.__main__:main',
        ],
    },

    include_package_data=True,
    zip_safe=False,

    classifiers=[
        'Not on PyPI'
    ],

)
