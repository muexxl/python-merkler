try:
    from setuptools import setup

except ImportError:
    from disutils.core import setup

config = [
    'description': 'My Project',
    'author': 'Beppo',
    'url': 'url to My Project',
    'download_url': 'where to download at',
    'author_email': '2018Beppo@gmail.com',
    'version': '0.1',
    'install_requires': ['nose'],
    'packages': ['NAME'],
    'scripts': [],
    'name': 'projectname'
]

setup(**config)
