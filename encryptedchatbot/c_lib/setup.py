from distutils.core import setup
from distutils.core import Extension

'''
setup(
    name='emoji',
    ext_modules=[
        Extension(
            'emoji',
            ['emoji.c'],
            # include_dirs=['./'],
            # define_macros=[('FOO', '1')],
            # undef_macros=['BAR'],
            library_dirs=['/usr/bin/lib'],
            # libraries=['emoji']
        )
    ]
)
'''


def main():
    setup(
        name="libtecb",
        version="0.2",
        description="Telegram-Encrypted-Chat-Bot Encode and decode to emoji string",
        author="Riko",
        author_email="xxy1836@gmail.com",
        ext_modules=[
            Extension(
                "libtecb",
                ["libtecb.c"]
            )
        ]
    )


if __name__ == "__main__":
    main()
