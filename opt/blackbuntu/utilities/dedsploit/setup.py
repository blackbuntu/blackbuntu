from setuptools import setup, find_packages

# main setup method
setup(
    name = "dedsploit",
    version = "4.0.0",
    author = "Alan Cao",
    author_email = "ex0dus@codemuch.tech",
    description = "network auditing framework",
    license = "MIT",
    url = "https://github.com/ex0dus-0x/dedsploit",
    keywords=[
        'pentesting',
        'security',
        'network',
        'cli',
    ],
    packages = find_packages(exclude=('tests',)),
    entry_points = {
        'console_scripts': [
            'dedsploit=dedsploit.__main__:main'
        ],
    },
    install_requires=[
        'scapy',
        'nmap',
    ],
    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: End Users/Desktop',
        'Environment :: Console',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ]
)
