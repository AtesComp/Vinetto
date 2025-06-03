#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
module vinetto.py
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumb Database files
 Copyright (C) 2005, 2006 by Michel Roukine
 Copyright (C) 2019-2025 by Keven L. Ates

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
file_micro = "13"


import sys
import os
import fnmatch
import argparse
import signal

import vinetto.version as version
import vinetto.config as config
import vinetto.error as verror
import vinetto.processor as processor
import vinetto.esedb as esedb
import vinetto.utils as utils

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
        "\n" +
        "Verbose Mode Notes:\n" +
        "  Using the verbose switch (-v, --verbose) and the quiet switch cause the\n" +
        "  terminal output to be treated differently based on the switch usage\n" +
        "    Level:   Mode:    Switch:   Output:\n"
        "     -1      Quiet     -q       Errors\n" +
        "      0      Standard  N/A      output + Errors + Warnings\n" +
        "      1      Verbose   -v       Standard + Extended + Info\n" +
        "      2      Enhanced  -vv      Verbose + Unused\n" +
        "      3      Full      -vvv     Enhanced + Missing\n" +
        "    where Quiet indicates no output other than error messages\n" +
        "          Standard indicates normal informative output\n" +
        "          Verbose adds Extended header, cache, and additional Info messages\n" +
        "          Enhanced add any data marked Unused or zero state\n" +
        "          Full expands empty data section output instead of \"Empty\"\n" +
        "      and Errors are error messages explaining termination\n" +
        "          Warnings are warning messages indicating processing issues\n" +
        "          Info are information messages indicating processing states\n" +
        "\n"
        )
    strEpilog = (
        "--- " + strProg + " " + version.STR_VERSION + " ---\n" +
        "Based on the original Vinetto by " + version.original_author[0] + "\n" +
        "Author: " + version.author[0] + "\n" +
        strProg + " is open source software\n" +
        "  See: " + version.location
        )
    strNotVerbose = "\nFor more detailed help notes, use -v"

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=strDesc,
                                     epilog=strEpilog + strNotVerbose, add_help=False)
    parser.add_argument("-h", "-?", "--help", action="store_true", dest="arg_help",
                        help=("show this help message and exit, use -v for more details"))
    parser.add_argument("-e", "--edb", dest="edbfile", metavar="EDBFILE",
                        help=("examine EDBFILE (Extensible Storage Engine Database) for\n" +
                              "original thumbnail filenames\n" +
                              "NOTE: -e without an INFILE explores EDBFILE extracted data\n" +
                              "NOTE: Automatic mode will attempt to use ESEDB without -e"))
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
                        help=("write thumbnails to DIR\n" +
                              "NOTE: -o requires INFILE"))
    parser.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                        help=("quiet output: Errors only\n" +
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
                        help=("verbose output, each use increments output level: 0 (Standard)\n" +
                              "1 (Verbose), 2 (Enhanced), 3 (Full)"))
    parser.add_argument("--version", action="version", version=strEpilog)
    parser.add_argument("infile", nargs="?",
                        help=("depending on operating mode (see mode option), either a location\n" +
                              "to a thumbnail file (\"Thumb.db\" or similar) or a directory"))
    pargs = parser.parse_args()

    if (pargs.arg_help):
        if (pargs.verbose > 0):
            parser.epilog = strNote + strEpilog
        parser.print_help()
        parser.exit(0)

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
            raise verror.InputError(strError + config.ARGS.infile + " does not exist")
        if (config.ARGS.mode == "f"):  # Traditional Mode...
            if not os.path.isfile(config.ARGS.infile):  # ...NOT a file?
                raise verror.InputError(strError + config.ARGS.infile + " not a file")
        else:  # Directory, Recursive Directory, or Automatic Mode...
            if not os.path.isdir(config.ARGS.infile):  # ...NOT a directory?
                raise verror.InputError(strError + config.ARGS.infile + " not a directory")
            # Add ending '/' as needed...
            if not config.ARGS.infile.endswith('/'):
                config.ARGS.infile += "/"

        if not os.access(config.ARGS.infile, os.R_OK):  # ...NOT readable?
            raise verror.InputError(strError + config.ARGS.infile + " not readable")
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
                raise verror.OutputError(strError + "Cannot create " + config.ARGS.outdir)
        else:  # ...exists...
            if not os.path.isdir(config.ARGS.outdir):  # ...NOT a directory?
                raise verror.OutputError(strError + config.ARGS.outdir + " is not a directory")
            elif not os.access(config.ARGS.outdir, os.W_OK):  # ...NOT writable?
                raise verror.OutputError(strError + config.ARGS.outdir + " not writable")
        # Add ending '/' as needed...
        if not config.ARGS.outdir.endswith('/'):
            config.ARGS.outdir += "/"

        # Remove existing URL file...
        if os.path.exists(config.ARGS.outdir + config.THUMBS_FILE_SYMS):
            os.remove(config.ARGS.outdir + config.THUMBS_FILE_SYMS)
    return


def getESEDB():
    strType = " (ESEDB): "

    # Setup ESEDB File test...
    bEDBErrorOut = True
    strReport = " Error"
    strEDBFileReport = "Given ESEDB ("
    if (config.ARGS.mode == "a" and config.ARGS.edbfile == None):
        bEDBErrorOut = False
        strReport = " Warning"
        strEDBFileReport = "Default ESEDB ("
        # Try Vista+ first (newer ESEDB location)...
        strEDBFile = os.path.join(config.ARGS.infile, config.OS_WIN_ESEDB_VISTA +
                                                      config.OS_WIN_ESEBD_COMMON +
                                                      config.OS_WIN_ESEBD_FILE)
        if not os.path.exists(strEDBFile):  # ...NOT exists?
            # Fallback to XP (older ESEDB location)...
            strEDBFile = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_XP +
                                                          config.OS_WIN_ESEDB_XP +
                                                          config.OS_WIN_ESEBD_COMMON +
                                                          config.OS_WIN_ESEBD_FILE)
            if not os.path.exists(strEDBFile):  # ...NOT exists?
                # Nothing available...
                strEDBFile = None
        config.ARGS.edbfile = strEDBFile

    if (config.ARGS.edbfile == None):
        return False

    strEDBFileReport += config.ARGS.edbfile + ")"

    # Test ESEDB File parameter...
    bProblem = False
    if not os.path.exists(config.ARGS.edbfile):  # ...NOT exists?
        bProblem = True
        strErrorMsg = strReport + strType + strEDBFileReport + " does not exist"
    elif not os.path.isfile(config.ARGS.edbfile):  # ...NOT a file?
        bProblem = True
        strErrorMsg = strReport + strType + strEDBFileReport + " is not a file"
    elif not os.access(config.ARGS.edbfile, os.R_OK):  # ...NOT readable?
        bProblem = True
        strErrorMsg = strReport + strType + strEDBFileReport + " not readable"

    if (bProblem):
        if bEDBErrorOut:
            raise verror.ESEDBError(strErrorMsg)
        elif (config.ARGS.verbose >= 0):
            sys.stderr.write(strErrorMsg + "\n")

    # ESEDB: Process data...
    config.ESEDB = esedb.ESEDB()
    if ( config.ESEDB.prepare() ):  # ...open...
        config.ESEDB.load()         # ...read, close...
    if (not config.ESEDB.isLoaded()):   # ...not loaded?...
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: Skipping ESEDB enhanced processing\n")

    return config.ESEDB.isLoaded()


# ================================================================================
#
# MAIN
#
# ================================================================================

def main():
#    def signal_handler(sig, frame):
#        #signal.signal(sig, signal.SIG_IGN)  # ...ignore additional signals
#        sys.stderr.write("Exiting Vinetto...\n")
#        sys.exit(0)
#
#    signal.signal(signal.SIGINT,  signal_handler)
#    signal.signal(signal.SIGTERM, signal_handler)
#    signal.signal(signal.SIGQUIT, signal_handler)

    sys.stdout.write( "Vinetto: Version {}\n".format(version.STR_VERSION) )
    if ( sys.version_info < (3, 0) ):
        sys.stdout.write( "Vinetto (version {}) requires Python 3!\n".format(version.STR_VERSION) )
        sys.exit(1)

    config.ARGS = getArgs()

    try:
        testInput()

        testOutput()

        # Unify QUIET and VERBOSE modes...
        if (config.ARGS.quiet):
            if (config.ARGS.verbose > 0):
                config.ARGS.quiet = False  # ..turn off quiet
            else:
                config.ARGS.verbose = -1  # ...store quiet as a verbose setting


        # Correct MD5 mode...
        if (config.ARGS.md5force) and (config.ARGS.md5never):
            config.ARGS.md5force = False

        if (config.ARGS.edbfile != None or config.ARGS.mode == "a"):
            getESEDB()

        utils.prepareSymLink()

        # Process
        # ============================================================
        if (config.ARGS.infile == None and config.ARGS.edbfile != None):
            config.ESEDB.examine()
        else:
            vProcessor = processor.Processor()
            if (config.ARGS.mode == "f"):  # Traditional Mode
                vProcessor.processThumbFile(config.ARGS.infile)
            elif (config.ARGS.mode == "d"):  # Directory Mode
                vProcessor.processDirectory(config.ARGS.infile)
            elif (config.ARGS.mode == "r"):  # Recursive Directory Mode
                vProcessor.processRecursiveDirectory()
            elif (config.ARGS.mode == "a"):  # Automatic Mode - File System
                vProcessor.processFileSystem()
            else:  # Unknown Mode - should never occur
                raise verror.ModeError(" Error (Mode): Unknown mode (" + config.ARGS.mode + ") to process " + config.ARGS.infile)
    except verror.VinettoError as ve:
        ve.printError()
        sys.exit(ve.iExitCode)
