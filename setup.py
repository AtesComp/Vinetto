import os
from setuptools import setup
from src.vinetto.version import __major__, __minor__, __micro__, __maintainer__, __author__, __location__

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
  name = 'vinetto',
  version = __major__ + '.' + __minor__ + '.' + __micro__,
  include_package_data = True,
  packages = ['vinetto'],
  package_dir = {'vinetto': 'src/vinetto'},
  package_data = {'vinetto': ['data/*', 'lib/*']},
  entry_points = {'console_scripts': ['vinetto=vinetto.vinetto:main']},
  description = 'Vinetto: The Thumbnail File Parser',
  long_description = read('ReadMe.md'),
  long_description_content_type = 'text/markdown',
  author = __author__,
  author_email = 'rukin@users.sf.net',
  maintainer = __maintainer__,
  maintainer_email = 'atescomp@gmail.com',
  url = __location__,
  license = 'GNU GPLv3',
  platforms = 'LINUX',
)
