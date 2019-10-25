# Vinetto

A thumbnail file parser.  Based on the original Vinetto by Michel Roukine

Usage Overview:
--------------

  Vinetto is a thumbnail file (i.e., thumbs.db) parser that can
  read a variety of these files.  This is a much needed update
  to the latest original Vinetto (version 0.7).

  This version is designed to be cross compatible between Python
  2 and 3.

```
    usage: vinetto [-h] [--version] [-o DIR] [-H] [-U] [-q] [-s] thumbfile

    Vinetto - The Thumbnail File Parser

    positional arguments:
      thumbfile   an input thumbnail file, like "Thumb.db"

    optional arguments:
      -h, --help  show this help message and exit
      --version   show program's version number and exit
      -o DIR      write thumbnails to DIR
      -H          write html report to DIR, requires -o
      -U          use utf8 encodings
      -q          quiet output
      -s          create symlink of the image realname to the numbered name in
                  DIR/.thumbs, requires -o

    Vinetto 0.8.0
    Based on the original Vinetto by Michel Roukine.
    Updated by Keven L. Ates
    Vinetto is open source software.
      See: https://github.com/AtesComp/Vinetto
```

Exit Codes:
--------------

  Vinetto reports a number of exit codes depending on its ability
  to perform certain tasks:

```
   0 - Normal termination
   2 - Argument parsing error
  10 - Input file errors
  11 - Output directory errors
  12 - Input file Header Signature error (not d0cf11e0a1b11ae1 or 0e11fc0dd0cf11e0)
  13 - Thumbnail output subdirectory error
  14 - Expecting JPEG EOI (End of Image)
  15 - Stream length doesn't match reported Header 1 length
  16 - Stream length doesn't match reported Header 2 length
  17 - Header 2 not found
  18 - Symlink create error
```

Installation:
--------------

  To install from the source directory:

```
    sudo -H pip install .
```

  To uninstall:

```
    sudo -H pip uninstall vinetto
```
