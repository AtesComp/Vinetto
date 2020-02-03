# Vinetto

Vinetto is a thumbnail file (i.e., thumbs.db) parser that can read a variety of
these files.  Based on the original Vinetto by Michel Roukine.

This is a much needed update to the last original Vinetto (version 0.7).

This version should be compatible with Python 2 and 3.  It should work on
Linux, Mac, and Windows.  Testing has currently been limited to Linux.

## Project Overview

1. **Context** : Older Windows systems (98, ME, 2000, XP, and Server 2003) can
store a thumb cache containing thumbnails and metadata of image files found in
the directories of its FAT32 or NTFS filesystems.  Newer Windows systems
(Vista, 7, 8, 10, other related Editions, and Server versions) use a unified
thumb cache system for each user.
   1. For older OS systems, thumbnails and associated metadata are stored in
   Thumbs.db files in each directory.  Thumbs.db files are undocumented OLE
   structured files.

   2. For newer OS systems, thumbnails and associated metadata are stored in
   thumbcache_\*.db files in each user's directory at:
     "Users/\*/AppData/Local/Microsoft/Windows/Explorer/"

   3. When an image file has been deleted from the filesystem, the related
   thumbnail and associated metadata may remain stored in the thumb cache
   files.

   4. Whether deleted or not, the data contained in the thumb cache files
   are an helpful source of information to the forensics investigator.  It
   may provide important resources related to activity associated with the
   images.

2. **Intention** : Vinetto extracts thumbnails and associated metadata from
thumb cache files.  Additionally, a thumbnail's Thumb Cache ID is cross checked
to extract file matadata, including possible original file name, from a
defaults or specified ESEDB (Windows.edb) file.  This process uses the python
libraries from "libesedb" to find and extract the relevant file metadata.
Vinetto will function according to four modes:
   1. *file* : Vinetto extracts thumbnail images and metadata from specified
   cache files.  **This is the default operating mode.**
      - Local directory Thumbs.db are processed.
      - User Thumbcache_\*.db files are processed.
      - Thumb Cache IDs are cross checked to extract any relevant metadata
      from a specified ESEDB file.

   2. *directory* : Vinetto processes any found \*.db files in the specified
   BASE directory.
      - It checks for consistency between the specified directory's content and
      its related Thumbs.db file (i.e., it reports thumbnails that have a
      missing associated file in the directory).
      - It processes any Thumbcache_\*.db files.
      - As per *file*, Thumb Cache IDs are cross checked to extract any relevant
      metadata from a specified ESEDB file.

   3. *recursive* : Vinetto processes any found \*.db files from the specified
   BASE directory recursively down its directory tree.
      - As per *directory*, it check for consistency between a subdirectory's
      content and its related Thumbs.db file (i.e., it reports thumbnails that
      have a missing associated file in the directory).
      - It processes any Thumbcache_\*.db files.
      - As per *file*, Thumb Cache IDs are cross checked to extract any relevant
      metadata from a specified ESEDB file.

   4. *automatic* : Vinetto will process the specified BASE directory as a
   Windows OS partition.
      - It checks the BASE directory to be consistent with Vista+ OS version.
      If less than Vista, it processes as per *recursive*.  If Vista+, it
      processes Thumbcache_\*.db files from each User directory:
        "Users/*/AppData/Local/Microsoft/Windows/Explorer/"
      - It attempts to cross check Thumb Cache IDs from the Windows.edb file in
      the **default location** or in a specified "ESEDB" file.

3. **Purpose** : Vinetto will help \*nix-based forensics investigators to:
   1. easily preview thumbnails of images (existing or deleted) on Windows
   systems,

   2. obtain metadata (dates, path, ...) about those images.

4. **Miscellaneous** : Vinetto is intended to be integrated into forensics
liveCD like FCCU GNU/Linux Forensic Boot CD.

## Requirements

1. Python-2.3 or later including standard libraries.

2. PIL or Pillow.  PIL (Python Imaging Library) 1.1.5 or later.  Pillow is used
by the maintainer.  PIL is used to attempt correct reconstitution of Type 1
thumbnails (see Limitations below).

## Limitations

1. For ***Thumbs.db*** files, Windows(R)(TM) uses at least two format types to
store these thumbnails:
   1. An older format that seems to consist of jpeg-like images with special
   header, huffman, and quantization data.  As such,
   ***Vinetto may not reconstitute some Type 1 thumbnails correctly.***
   The PIL Image library is used to attempt proper reconstitution, but may fail
   in certain circumstances.

   2. A newer format fully compliant with the JPEG format.  Vinetto writes this
   type to file directly.

2. The current ***thumbcache*** files embed fully compliant JPEG, PNG, and BMP
formats which Vinetto writes directly.

3. The Windows.edb and other ESEDB files can become corrupt.  If there are
problems with Vinetto reading the file, it may need to be fixed.  To fix this
issue, use the Windows built-in command ***esentutil***  with the ***/p*** option
and point it at the ESEDB file you want to fix.  It may need to be run several
times to fix the file.

Vinetto has been tested on a modern Linux distribution.  The code has been
modified to use common Python packages and methods not specific to the Linux
OS.  Therefore, it should operate on BSD deriviatives, such as Darwin(R)(TM),
and Windows(R)(TM) OSes as well. YMMV.

## Usage Overview:

```
    usage: vinetto [-h] [-e EDBFILE] [-H] [-m [{f,d,r,a}]] [--md5] [--nomd5]
                [-o DIR] [-q] [-s] [-U] [-v] [--version]
                [infile]

    Vinetto.py - The Thumbnail File Parser

    positional arguments:
    infile                depending on operating mode (see mode option), either a location
                            to a thumbnail file ("Thumb.db" or similar) or a directory

    optional arguments:
    -h, -?, --help        show this help message and exit
    -e EDBFILE, --edb EDBFILE
                            examine EDBFILE (Extensible Storage Engine Database) for
                            original thumbnail filenames
                            NOTE: -e without an INFILE explores EDBFILE extracted data
                            NOTE: Automatic mode will attempt to use ESEDB without -e
    -H, --htmlrep         write html report to DIR (requires option -o)
    -m [{f,d,r,a}], --mode [{f,d,r,a}]
                            operating mode: "f", "d", "r", or "a"
                            where "f" indicates single file processing (default)
                                    "d" indicates directory processing
                                    "r" indicates recursive directory processing from a
                                        starting directory
                                    "a" indicates automatic processing using well known
                                        directories starting from a base directory
    --md5                 force the MD5 hash value calculation for an input file
                            Normally, the MD5 is calculated when a file is less than
                            0.5 GiB in size
                            NOTE: --nomd5 overrides --md5
    --nomd5               skip the MD5 hash value calculation for an input file
    -o DIR, --outdir DIR  write thumbnails to DIR
                            NOTE: -o requires INFILE
    -q, --quiet           quiet output: Errors only
                            NOTE: -v overrides -q
    -s, --symlinks        create symlink from the the image realname to the numbered name
                            in DIR/.thumbs (requires option -o)
                            NOTE: A Catalog containing the realname must exist for this
                                option to produce results OR a Windows.edb must be given
                                (-e) to find and extract possible file names
    -U, --utf8            use utf8 encodings
    -v, --verbose         verbose output, each use increments output level: 0 (Standard)
                            1 (Verbose), 2 (Enhanced), 3 (Full)
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

    Verbose Mode Notes:
    Using the verbose switch (-v, --verbose) and the quiet switch cause the
    terminal output to be treated differently based on the switch usage
        Level:   Mode:    Switch:   Output:
        -1      Quiet     -q       Errors
        0      Standard  N/A      output + Errors + Warnings
        1      Verbose   -v       Standard + Extended + Info
        2      Enhanced  -vv      Verbose + Unused
        3      Full      -vvv     Enhanced + Missing
        where Quiet indicates no output other than error messages
            Standard indicates normal informative output
            Verbose adds Extended header, cache, and additional Info messages
            Enhanced add any data marked Unused or zero state
            Full expands empty data section output instead of "Empty"
        and Errors are error messages explaining termination
            Warnings are warning messages indicating processing issues
            Info are information messages indicating processing states

    --- Vinetto.py 0.9.5 ---
    Based on the original Vinetto by Michel Roukine
    Author: Keven L. Ates
    Vinetto.py is open source software
    See: https://github.com/AtesComp/Vinetto
```

## Exit Codes

Vinetto reports a number of exit codes depending on its ability to perform
certain tasks:

```
   0 - Normal termination
   2 - Argument parsing error
  10 - Input errors
  11 - Output errors
  12 - Processing errors
  13 - Install errors
  14 - Entry errors (Stream, Cache)
  15 - Symlink errors
  16 - Mode errors
  17 - Report errors (HTML)
  18 - ESEDB file errors
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
