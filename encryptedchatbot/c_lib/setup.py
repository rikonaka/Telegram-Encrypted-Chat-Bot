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
        name="emoji",
        version="0.1",
        description="Encode and decode the emoji string",
        author="Name",
        author_email="your_email@gmail.com",
        ext_modules=[
            Extension(
                "emoji",
                ["emojimodule.c"]
            )
        ]
    )


if __name__ == "__main__":
    main()
