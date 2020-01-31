#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
module vinetto.py
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumb Database files
 Copyright (C) 2005, 2006 by Michel Roukine
 Copyright (C) 2019-2020 by Keven L. Ates

This file is part of Vinetto.

 Vinetto is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as published
 by the Free Software Foundation; either version 2 of the License, or (at
 your option) any later version.

 Vinetto is distributed in the hope that it will be
 useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License along
 with the vinetto package; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

-----------------------------------------------------------------------------
"""


file_major = "0"
file_minor = "1"
file_micro = "4"


import sys
import os
import fnmatch
import argparse

import vinetto.version as version
import vinetto.config as config
import vinetto.thumbfile as thumbfile
import vinetto.esedb as esedb


def getArgs():
    # Return arguments passed to vinetto on the command line...

    strProg = os.path.basename(__file__).capitalize()
    strDesc = strProg + " - The Thumbnail File Parser"
    strNote = (
        "Operating Mode Notes:\n" +
        "  Using the mode switch (-m, --mode) causes the input to be treated differently\n" +
        "  based on the mode selected\n" +
        "  File      (f): DEFAULT\n" +
        "    Use the input as a location to an individual thumbnail file to process\n" +
        "  Directory (d):\n" +
        "    Use the input as a directory containing individual thumbnail files where\n" +
        "    each file is automatically iterated for processing\n" +
        "  Recursive (r):\n" +
        "    Use the input as a BASE directory from which it and subdirectories are\n" +
        "    recursively searched for individual thumbnail files for processing\n" +
        "  Automatic (a):\n" +
        "    Use the input as a BASE directory of a partition to examine default\n" +
        "    locations for relevant thumbnail files to process\n" +
        "      Thumbcache Files:\n" +
        "        BASE/Users/*/AppData/Local/Microsoft/Windows/Explorer\n" +
        "          where '*' are user directories iterated automatically\n" +
        "      Windows.edb File:\n" +
        "        BASE/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb\n" +
        "    When the EDBFILE (-e, -edbfile switch) is given, it overrides the automated\n" +
        "    location\n" +
        "\n"
        )
    strEpilog = (
        "--- " + strProg + " " + version.STR_VERSION + " ---\n" +
        "Based on the original Vinetto by " + version.original_author[0] + "\n" +
        "Author: " + version.author[0] + "\n" +
        strProg + " is open source software\n" +
        "  See: " + version.location
        )

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=strDesc,
                                     epilog=(strNote + strEpilog), add_help=False)
    parser.add_argument("-h", "-?", "--help", action='help',
                        help=('show this help message and exit'))
    parser.add_argument("-e", "--edb", dest="edbfile", metavar="EDBFILE",
                        help=("examine EDBFILE (Extensible Storage Engine Database) for\n" +
                              "original thumbnail filenames\n" +
                              "NOTE: -e without an INFILE explores EDBFILE"))
    parser.add_argument("-H", "--htmlrep", action="store_true", dest="htmlrep",
                        help=("write html report to DIR (requires option -o)"))
    parser.add_argument("-m", "--mode", nargs="?", dest="mode", choices=["f", "d", "r", "a"],
                        default="f", const="f",
                        help=("operating mode: \"f\", \"d\", \"r\", or \"a\"\n" +
                              "  where \"f\" indicates single file processing (default)\n" +
                              "        \"d\" indicates directory processing\n" +
                              "        \"r\" indicates recursive directory processing from a\n" +
                              "              starting directory\n" +
                              "        \"a\" indicates automatic processing using well known\n" +
                              "              directories starting from a base directory"))
    parser.add_argument("--md5", action="store_true", dest="md5force",
                        help=("force the MD5 hash value calculation for an input file\n" +
                              "Normally, the MD5 is calculated when a file is less than\n" +
                              "0.5 GiB in size\n" +
                              "NOTE: --nomd5 overrides --md5"))
    parser.add_argument("--nomd5", action="store_true", dest="md5never",
                        help=("skip the MD5 hash value calculation for an input file"))
    parser.add_argument("-o", "--outdir", dest="outdir", metavar="DIR",
                        help=("write thumbnails to DIR"))
    parser.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                        help=("quiet output, supress warnings\n" +
                              "NOTE: -v overrides -q"))
    parser.add_argument("-s", "--symlinks", action="store_true", dest="symlinks",
                        help=("create symlink from the the image realname to the numbered name\n" +
                              "in DIR/" + config.THUMBS_SUBDIR + " (requires option -o)\n" +
                              "NOTE: A Catalog containing the realname must exist for this\n" +
                              "      option to produce results OR a Windows.edb must be given\n" +
                              "      (-e) to find and extract possible file names"))
    parser.add_argument("-U", "--utf8", action="store_true", dest="utf8",
                        help=("use utf8 encodings"))
    parser.add_argument("-v", '--verbose', action='count', default=0,
                        help=("verbose output, print info messages - each use increments output\n" +
                              "level"))
    parser.add_argument("--version", action="version", version=strEpilog)
    parser.add_argument("infile", nargs="?",
                        help=("depending on operating mode (see mode option), either a location\n" +
                              "to a thumbnail file (\"Thumb.db\" or similar) or a directory"))
    pargs = parser.parse_args()

    if (pargs.outdir == None):  # ...output NOT given...
        if (pargs.htmlrep):
            parser.error("-H option requires -o with a directory name")
        if (pargs.symlinks):
            parser.error("-s option requires -o with a directory name")
    else:  # ...output given...
        if (pargs.infile == None):  # ...then, input is required...
            parser.error("No input file or directory specified")

    if (pargs.edbfile == None):
        if (pargs.infile == None):
            parser.error("No input file or directory specified")

    if (pargs.mode == None):
      parser.error("Operating mode must be specified")

    return (pargs)


def processDirectory(thumbDir, filenames=None):
    # Search for thumbnail cache files:
    #  Thumbs.db, ehthumbs.db, ehthumbs_vista.db, Image.db, Video.db, TVThumb.db, and musicThumbs.db
    #
    #  thumbcache_*.db (2560, 1920, 1600, 1280, 1024, 768, 256, 96, 48, 32, 16, sr, wide, exif, wide_alternate, custom_stream)
    #  iconcache_*.db

    #includes = ['*humbs.db', '*humbs_*.db', 'Image.db', 'Video.db', 'TVThumb.db', 'thumbcache_*.db', 'iconcache_*.db']
    includes = ['*.db']

    if (filenames == None):
        filenames = []
        with os.scandir(thumbDir) as iterFiles:
            for fileEntry in iterFiles:
                if fileEntry.is_file():
                    filenames.append(fileEntry.name)

    # Include files...
    files = []
    for pattern in includes:
        for filename in fnmatch.filter(filenames, pattern):
            files.append(os.path.join(thumbDir, filename))

    # TODO: Check for "Thumbs.db" file and related image files in current directory
    # TODO: This may involve passing info into processThumbFile() and following functionality
    # TODO: to check existing image file names against stored thumbnail IDs

    for thumbFile in files:
        thumbfile.processThumbFile(thumbFile)
        if (config.EXIT_CODE > 0):
            sys.exit(config.EXIT_CODE)

    return


def processRecursiveDirectory():
    # Walk the directories from given directory recursively down...
    for dirpath, dirnames, filenames in os.walk(config.ARGS.infile):
        processDirectory(dirpath, filenames)
        if (config.EXIT_CODE > 0):
            sys.exit(config.EXIT_CODE)
    return


def processFileSystem():
    #
    # Process well known Thumb Cache DB files with ESE DB enhancement (if available)
    #

    strUserBaseDirVista = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_VISTA)
    strUserBaseDirXP = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_XP)

    # Vista+
    # ============================================================
    if os.path.isdir(strUserBaseDirVista):
        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info: FS - Detected a Windows Vista-like partition, processing each user's Thumbcache DB files\n")
        # For Vista+, only process the User's Explorer subdirectory containing Thumbcache DB files...
        with os.scandir(strUserBaseDirVista) as iterDirs:
            for entryUserDir in iterDirs:
                if not entryUserDir.is_dir():
                    continue
                userThumbsDir = os.path.join(entryUserDir.path, config.OS_WIN_THUMBCACHE_DIR)
                if not os.path.exists(userThumbsDir):  # ...NOT exists?
                    if (not config.ARGS.quiet):
                        sys.stderr.write(" Warning: Skipping %s - does not contain %s\n" % (entryUserDir.path, config.OS_WIN_THUMBCACHE_DIR))
                else:
                    processDirectory(userThumbsDir)
                    if (config.EXIT_CODE > 0):
                        sys.exit(config.EXIT_CODE)

    # XP
    # ============================================================
    elif os.path.isdir(strUserBaseDirXP):
        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info: FS - Detected a Windows XP-like partition, processing all user subdirectories\n")
        # For XP, only process each User's subdirectories...
        with os.scandir(strUserBaseDirXP) as iterDirs:
            for entryUserDir in iterDirs:
                if not entryUserDir.is_dir():
                    continue
                processDirectory(entryUserDir)
                if (config.EXIT_CODE > 0):
                    sys.exit(config.EXIT_CODE)

    # Other / Unidentified
    # ============================================================
    else:
        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info: FS - Generic partition, processing all subdirectories (recursive operating mode)\n")
        processDirectory(config.ARGS.infile)
        if (config.EXIT_CODE > 0):
            sys.exit(config.EXIT_CODE)

    return


# ================================================================================
#
# MAIN Support Functions
#
# ================================================================================

def testInput():
    strError = " Error (Input): "

    # Test Input File parameter...
    if (config.ARGS.infile != None):
        if not os.path.exists(config.ARGS.infile):  # ...NOT exists?
            sys.stderr.write(strError + "%s does not exist\n" % (config.ARGS.infile))
            config.EXIT_CODE = 10
            return
        if (config.ARGS.mode == "f"):  # Traditional Mode...
            if not os.path.isfile(config.ARGS.infile):  # ...NOT a file?
                sys.stderr.write(strError + "%s not a file\n" % (config.ARGS.infile))
                config.EXIT_CODE = 10
                return
        else:  # Directory, Recursive Directory, or Automatic Mode...
            if not os.path.isdir(config.ARGS.infile):  # ...NOT a directory?
                sys.stderr.write(strError + "%s not a directory\n" % (config.ARGS.infile))
                config.EXIT_CODE = 10
                return
            # Add ending '/' as needed...
            if not config.ARGS.infile.endswith('/'):
                config.ARGS.infile += "/"

        if not os.access(config.ARGS.infile, os.R_OK):  # ...NOT readable?
            sys.stderr.write(strError + "%s not readable\n" % (config.ARGS.infile))
            config.EXIT_CODE = 10
            return
    return


def testOutput():
    strError = " Error (Output): "

    # Test Output Directory parameter...
    if (config.ARGS.outdir != None):
        if not os.path.exists(config.ARGS.outdir):  # ...NOT exists?
            try:
                os.mkdir(config.ARGS.outdir)  # ...make it
                if (config.ARGS.verbose > 0):
                    sys.stderr.write(" Info: %s was created\n" % (config.ARGS.outdir))
            except EnvironmentError as e:
                sys.stderr.write(strError + "Cannot create %s\n" % (config.ARGS.outdir))
                config.EXIT_CODE = 11
                return
        else:  # ...exists...
            if not os.path.isdir(config.ARGS.outdir):  # ...NOT a directory?
                sys.stderr.write(strError + "%s is not a directory\n" % (config.ARGS.outdir))
                config.EXIT_CODE = 11
                return
            elif not os.access(config.ARGS.outdir, os.W_OK):  # ...NOT writable?
                sys.stderr.write(strError + "%s not writable\n" % (config.ARGS.outdir))
                config.EXIT_CODE = 11
                return
        # Add ending '/' as needed...
        if not config.ARGS.outdir.endswith('/'):
            config.ARGS.outdir += "/"

        # Remove existing URL file...
        if os.path.exists(config.ARGS.outdir + config.THUMBS_FILE_URLS):
            os.remove(config.ARGS.outdir + config.THUMBS_FILE_URLS)
    return


def testESEDB():
    strError = " Error"
    strType = " (ESEDB): "

    # Test ESEDB File parameter...
    bEDBErrorOut = True
    bEDBFileGood = False
    strEDBFileReport = config.ARGS.edbfile
    strErrorReport = strError + strType
    if (config.ARGS.mode == "a" and config.ARGS.edbfile == None):
        bEDBErrorOut = False
        strErrorReport = " Warning" + strType
        strEDBFileReport = "Default ESEDB"
        # Try Vista+ first (newer ESEDB location)...
        strEDBFile = os.path.join(config.ARGS.infile, config.OS_WIN_ESEDB_VISTA + config.OS_WIN_COMMON)
        if not os.path.exists(strEDBFile):  # ...NOT exists?
            # Fallback to XP (older ESEDB location)...
            strEDBFile = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_XP + config.OS_WIN_ESEDB_XP + config.OS_WIN_COMMON)
        config.ARGS.edbfile = strEDBFile
    if (config.ARGS.edbfile != None):
        # Testing EDBFILE parameter...
        if not os.path.exists(config.ARGS.edbfile):  # ...NOT exists?
            if (bEDBErrorOut or not config.ARGS.quiet):
                sys.stderr.write("%s%s does not exist\n" % (strErrorReport, strEDBFileReport))
            if bEDBErrorOut:
                config.EXIT_CODE = 18
                return
        elif not os.path.isfile(config.ARGS.edbfile):  # ...NOT a file?
            if (bEDBErrorOut or not config.ARGS.quiet):
                sys.stderr.write("%s%s is not a file\n" % (strErrorReport, strEDBFileReport))
            if bEDBErrorOut:
                config.EXIT_CODE = 18
                return
        elif not os.access(config.ARGS.edbfile, os.R_OK):  # ...NOT readable?
            if (bEDBErrorOut or not config.ARGS.quiet):
                sys.stderr.write("%s%s not readable\n" % (strErrorReport, strEDBFileReport))
            if bEDBErrorOut:
                config.EXIT_CODE = 18
                return

        # ESEDB: Prepare (open)...
        bEDBFileGood = esedb.prepareESEDB()
        if (config.EXIT_CODE > 0):
            return

        # ESEDB: Load...
        if bEDBFileGood:  # ...ESEDB good?...
            bEDBFileGood = esedb.loadESEDB()

        # ESEDB: Check for problems...
        if not bEDBFileGood:  # ...ESEDB bad?...
            if (not config.ARGS.quiet):
                sys.stderr.write(" Warning: Skipping ESEDB enhanced processing\n")

        # ESEDB: Close...
        if (config.ESEDB_FILE != None):
            config.ESEDB_TABLE = None
            config.ESEDB_FILE.close()
    return


def prepareSymLink():
    if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
        if not os.path.exists(config.ARGS.outdir + config.THUMBS_SUBDIR):
            try:
                os.mkdir(config.ARGS.outdir + config.THUMBS_SUBDIR)
            except EnvironmentError:
                sys.stderr.write(" Error (Symlink): Cannot create directory %s\n" % config.ARGS.outdir + config.THUMBS_SUBDIR)
                config.EXIT_CODE = 15
                return
    return


# ================================================================================
#
# MAIN
#
# ================================================================================

def main():
    config.ARGS = getArgs()

    testInput()
    if (config.EXIT_CODE > 0):
        sys.exit(config.EXIT_CODE)

    testOutput()
    if (config.EXIT_CODE > 0):
        sys.exit(config.EXIT_CODE)

    # Correct QUIET mode...
    if (config.ARGS.quiet) and (config.ARGS.verbose > 0):
        config.ARGS.quiet = False

    # Correct MD5 mode...
    if (config.ARGS.md5force) and (config.ARGS.md5never):
        config.ARGS.md5force = False

    testESEDB()
    if (config.EXIT_CODE > 0):
        sys.exit(config.EXIT_CODE)

    prepareSymLink()
    if (config.EXIT_CODE > 0):
        return

    # Process
    # ============================================================
    if (config.ARGS.infile == None and config.ARGS.edbfile != None):
        esedb.examineESEDB()
    elif (config.ARGS.mode == "f"):  # Traditional Mode
        thumbfile.processThumbFile(config.ARGS.infile)
    elif (config.ARGS.mode == "d"):  # Directory Mode
        processDirectory(config.ARGS.infile)
    elif (config.ARGS.mode == "r"):  # Recursive Directory Mode
        processRecursiveDirectory()
    elif (config.ARGS.mode == "a"):  # Automatic Mode - File System
        processFileSystem()
    else:  # Unknown Mode - should never occur
        sys.stderr.write(" Error (Mode): Unknown mode (%s) to process %s\n" % (config.ARGS.mode, config.ARGS.infile))
        config.EXIT_CODE = 16

    if (config.EXIT_CODE > 0):
        sys.exit(config.EXIT_CODE)
