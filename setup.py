import os
from setuptools import setup
from src.vinetto import version

# Utility function to read the ReadMe.md file...
#   Used for the long_description.  It's nice, because now:
#     1) we have a top level ReadMe.md file and
#     2) it's easier to type in the ReadMe.md file than to put a raw string in below
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
  # METADATA...
  name = 'vinetto',
  version = version.STR_VERSION,
  url = version.location,
  download_url = "https://github.com/AtesComp/Vinetto/archive/master.zip",
  project_urls = {
    "Bug Tracker": "https://github.com/AtesComp/Vinetto/issues",
    "Documentation": "https://github.com/AtesComp/Vinetto/blob/master/ReadMe.md",
    "Source Code": "https://github.com/AtesComp/Vinetto.git",
  },
  author = version.author[0],
  author_email = version.author[1],
  maintainer = version.maintainer[0][0],
  maintainer_email = version.maintainer[0][1],
  description = 'Vinetto: The Thumbnail File Parser',
  license = 'GNU GPLv3',
  long_description = read('ReadMe.md'),
  long_description_content_type = 'text/markdown',
  platforms = ['LINUX', 'MAC', 'WINDOWS'],
  # OPTIONS...
  entry_points = {'console_scripts': ['vinetto=vinetto.vinetto:main']},
  include_package_data = True,
  packages = ['vinetto'],
  package_dir = {'vinetto': 'src/vinetto'},
  package_data = {'vinetto': ['data/*', 'lib/*']},
)
