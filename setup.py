try:
    from setuptools import setup

except ImportError:
    from disutils.core import setup

config = [
    'description': 'Merkler',
    'author': 'Muexx',
    'url': 'https://github.com/muexxl/python-merkler',
    'download_url': 'https://github.com/muexxl/python-merkler.git',
    'author_email': 'stephan.muekusch@gmail.com',
    'version': '0.1',
    'install_requires': ['nose'],
    'packages': ['merkler'],
    'scripts': [],
    'name': 'merkler'
]

setup(**config)
