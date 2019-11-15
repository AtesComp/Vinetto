# Vinetto

Vinetto is a thumbnail file (i.e., thumbs.db) parser that can read a variety of
these files.  Based on the original Vinetto by Michel Roukine.

This is a much needed update to the latest original Vinetto (version 0.7).

This version should be compatible with Python 2 and 3.  It should work on
Linux, Mac, and Windows.  Testing has currently been limited to Linux.

## Project Overview

1. **Context** : The Windows systems (98, ME, 2000 and XP) can store thumbnails
and metadata of the picture files contained in the directories of its FAT32 or
NTFS filesystems.
   1. Thumbnails and associated metadata are stored in Thumbs.db files.
   Thumbs.db files are undocumented OLE structured files.

   2. When an image file has been deleted from the filesystem, the related
   thumbnail and associated metadata remain stored in the Thumbs.db file.  The
   data contained in those Thumbs.db files are an helpful source of information
   to the forensics investigator.

2. **Intention** : Vinetto extracts thumbnails and associated metadata from
Thumbs.db files.  Vinetto will function according to three modes:
   1. *elementary* : Vinetto extracts thumbnails and metadata from specified
   Thumbs.db files.  **This is the current operating mode.**

   2. *directory* : Vinetto will check for consistency between directory
   content and a related Thumbs.db file.  I.e., it will report thumbnails that
   have a missing associated file in the directory.

   3. *filesystem* : Vinetto will process whole FAT or NTFS partitions for
   thumbnail files and their images.

3. **Purpose** : Vinetto will help *nix-based forensics investigators to:
   1. easily preview thumbnails of deleted pictures on Windows systems,

   2. obtain informations (dates, path, ...) about those deleted images.

4. **Miscellaneous** : Vinetto is intended to be integrated into forensics
liveCD like FCCU GNU/Linux Forensic Boot CD.

## Requirements

1. Python-2.3 or later.

2. PIL or Pillow.  PIL (Python Imaging Library) 1.1.5 or later.  Pillow is used
by the maintainer.  PIL is used to attempt correct reconstitution of Type 1
thumbnails (see Limitations below).

## Limitations

Windows(R)(TM) uses at least two format types to store thumbnails in its
Thumbs.db files.  Vinetto categorizes these formats as Type 1 and Type 2:

1. Type 1 seems to be a family of jpeg-alike formats with special headers,
huffman, and quantization tables.  As such, ***Vinetto may not reconstitute
some Type 1 thumbnails correctly.***  PIL Image is used to attempt proper
reconstitute, but may fail in certain circumstances.

2. Type 2 is compliant to the JPEG format.  Vinetto writes this type to file
directly.

Vinetto has been tested on a modern Linux distribution.  The code has been
modified to use common Python packages and methods not specific to the Linux
OS.  Therefore, it should operate on BSD deriviatives, such as Darwin(R)(TM),
and Windows(R)(TM) OSes as well. YMMV.

## Usage Overview:

```
    usage: vinetto [-h] [--version] [-o DIR] [-H] [-U] [-q] [-s] [-m {d,r}] infile

    Vinetto.py - The Thumbnail File Parser

    positional arguments:
    infile                an input file, depending on mode, such as a
                            thumbnail file ("Thumb.db" or similar) or a directory

    optional arguments:
    -h, --help            show this help message and exit
    --version             show program's version number and exit
    -o DIR, --outdir DIR  write thumbnails to DIR
    -H, --htmlrep         write html report to DIR (requires option -o)
    -U, --utf8            use utf8 encodings
    -q, --quiet           quiet output
    -s, --symlinks        create symlink from the the image realname to the numbered name
                            in DIR/.thumbs (requires option -o)
                            NOTE: A Catalog containing the realname must exist for this
                                option to produce results
    -m {d,r}, --mode {d,r}
                            operating mode: "d" or "r"
                            where "d" indicates directory processing
                                    "r" indicates recursive directory processing from a
                                        starting directory

    --- Vinetto 0.8.4 ---
    Based on the original Vinetto by Michel Roukine
    Updated by Keven L. Ates
    Vinetto is open source software
      See: https://github.com/AtesComp/Vinetto
```

## Exit Codes

Vinetto reports a number of exit codes depending on its ability to perform
certain tasks:

```
   0 - Normal termination
   2 - Argument parsing error
  10 - Input file errors
  11 - Output directory errors
  12 - Input file Header Signature error
  13 - Thumbnail output subdirectory error
  14 - Expecting JPEG EOI (End of Image)
  15 - Stream length doesn't match reported Header 1 length
  16 - Stream length doesn't match reported Header 2 length
  17 - Header 2 not found
  18 - Symlink create error
```

## Installation:

  To install from the source directory:

```
    sudo -H pip install .
```

  To uninstall:

```
    sudo -H pip uninstall vinetto
```
