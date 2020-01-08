# Vinetto

Vinetto is a thumbnail file (i.e., thumbs.db) parser that can read a variety of
these files.  Based on the original Vinetto by Michel Roukine.

This is a much needed update to the last original Vinetto (version 0.7).

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
thumb image cache files.  Vinetto will function according to four modes:
   1. *file* : Vinetto extracts thumbnail images and metadata from specified
   cache files.  **This is the current default operating mode.**
      - Local directory Thumbs.db are processes.
      - **TODO:** It will also process Thumbcache_\*.db files.
      - **TODO:** It will attempt to cross check Thumb Ids with file names in a
      specified Windows.edb file. This process uses the python libraries from
      libesedb to find and extract the relevant file information.

   2. *directory* : Vinetto processes any found \*.db files in the specified
   BASE directory.
      - **TODO:** It will check for consistency between the specified
      directory's content and its related Thumbs.db file.  I.e., it will report
      thumbnails that have a missing associated file in the directory.
      - **TODO:** It will also process Thumbcache_\*.db files.
      - **TODO:** As per default, it will attempt to cross check Thumb Ids with
      file names in a specified Windows.edb file.

   3. *recursive* : Vinetto processes any found \*.db files from the specified
   BASE directory recursively down its directory tree.
      - **TODO:** It will check for consistency between a subdirectory's
      content and its related Thumbs.db file.  I.e., it will report
      thumbnails that have a missing associated file in its subdirectory.
      - **TODO:** It will also process Thumbcache_\*.db files.
      - **TODO:** As per default, it will attempt to cross check Thumb Ids with
      file names in a specified Windows.edb file.

   4. *automatic* : **TODO:** Vinetto will process the specified BASE
   directory as a Windows Vista+ OS partition.
      - **TODO:** It will processing thumbcache files from
      BASE/Users/*/AppData/Local/Microsoft/Windows/Explorer/
      - **TODO:** As per default, it will attempt to cross check Thumb Ids with
      file names in
      BASE/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb
      or in a specified Windows.edb file.

3. **Purpose** : Vinetto will help \*nix-based forensics investigators to:
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
***Thumbs.db*** files.  Vinetto categorizes these formats as Type 1 and Type 2:

1. Type 1 is an older format that seems to consist of jpeg-like images with
special header, huffman, and quantization data.  As such,
***Vinetto may not reconstitute some Type 1 thumbnails correctly.***
The PIL Image library is used to attempt proper reconstitution, but may fail
in certain circumstances.

2. Type 2 is a newer format and is fully compliant with the JPEG format.
Vinetto writes this type to file directly.  Additionally, the newer
***thumbcache*** files embed fully compliant JPEG, PNG, and BMP formats
which Vinetto also writes directly.

3. The Windows.edb and other ESEDB files can become corrupt.  If there are
problems with Vinetto reading the file, it may need to be fixed.  To fix this
issue, use the Windows built-in command ***esentutil***  with the ***/p*** option
and point it at the ESEDB file you want to fix.  It may need to be run several
time to fix the file.

Vinetto has been tested on a modern Linux distribution.  The code has been
modified to use common Python packages and methods not specific to the Linux
OS.  Therefore, it should operate on BSD deriviatives, such as Darwin(R)(TM),
and Windows(R)(TM) OSes as well. YMMV.

## Usage Overview:

```
    usage: vinetto [-h] [-e EDBFILE] [-H] [-m {d,r}] [--md5] [--nomd5] [-o DIR]
                [-q] [-s] [-U] [--version]
                infile

    Vinetto.py - The Thumbnail File Parser

    positional arguments:
    infile                an input file, depending on mode, such as a
                            thumbnail file ("Thumb.db" or similar) or a directory

    optional arguments:
    -h, --help            show this help message and exit
    -e EDBFILE, --edb EDBFILE
                            examine EDBFILE for original thumbnail filenames
    -H, --htmlrep         write html report to DIR (requires option -o)
    -m {d,r}, --mode {d,r}
                            operating mode: "d" or "r"
                            where "d" indicates directory processing
                                    "r" indicates recursive directory processing from a
                                        starting directory
    --md5                 force the MD5 hash value calculation for an input file
                            Normally, the MD5 is calculated when a file is less than
                            0.5 GiB in size
                            NOTE: --nomd5 overrides --md5
    --nomd5               skip the MD5 hash value calculation for an input file
    -o DIR, --outdir DIR  write thumbnails to DIR
    -q, --quiet           quiet output
    -s, --symlinks        create symlink from the the image realname to the numbered name
                            in DIR/.thumbs (requires option -o)
                            NOTE: A Catalog containing the realname must exist for this
                                option to produce results OR a Windows.edb must be given
                                (-e) to find and extract possible file names
    -U, --utf8            use utf8 encodings
    --version             show program's version number and exit

    Operating Mode Notes:
      Using the mode switch (-m, --mode) causes the input to be treated differently
      based on the mode selected
      File      (f): DEFAULT
        Use the input as a location to an individual thumbnail file to process
      Directory (d):
        Use the input as a directory containing individual thumbnail files where
        each file is automatically iterated for processing
      Recursive (r):
        Use the input as a BASE directory from which it and subdirectories are
        recursively searched for individual thumbnail files for processing
      Automatic (a):
        Use the input as a BASE directory of a partition to examine default
        locations for relevant thumbnail files to process
          Thumbcache Files:
            BASE/Users/*/AppData/Local/Microsoft/Windows/Explorer
              where '*' are user directories iterated automatically
          Windows.edb File:
            BASE/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb
        When the EDBFILE (-e, -edbfile switch) is given, it overrides the automated
        location

    --- Vinetto.py 0.8.6 ---
    Based on the original Vinetto by Michel Roukine
    Updated by Keven L. Ates
    Vinetto.py is open source software
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
  19 - EDB Input file errors
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
