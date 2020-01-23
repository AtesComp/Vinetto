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
file_micro = "2"


import sys
import os
import fnmatch
import errno
import argparse
from io import StringIO
from struct import unpack
from binascii import hexlify, unhexlify

import vinetto.version as version
import vinetto.config as config
import vinetto.report as report
import vinetto.tdb_catalog as tdb_catalog
import vinetto.tdb_streams as tdb_streams

from vinetto.utils import getFormattedWinToPyTimeUTC, cleanFileName, getEncoding, decodeBytes

from pkg_resources import resource_filename


IMAGE_TYPE_1_HEADER   = None
IMAGE_TYPE_1_QUANTIZE = None
IMAGE_TYPE_1_HUFFMAN  = None

HTTP_REPORT = None

STR_SEP = " ------------------------------------------------------"


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


def nextBlock(fileTDB, listSAT, iOffset, cEndian):
    # Return next block
    iSATIndex = iOffset // 128  # ...SAT index for search sector
    iSATOffset = iOffset % 128  # ...Sector offset within search sector
    iFileOffset = 512 + listSAT[iSATIndex] * 512 + iSATOffset * 4
    fileTDB.seek(iFileOffset)
    return unpack(cEndian+"L", fileTDB.read(4))[0]


def printBlock(strName, oleBlock):
    print("          Name: %s" % strName)
    print("          Type: %d (%s)" % (oleBlock["type"], config.OLE_BLOCK_TYPES[oleBlock["type"]]))
    if (config.ARGS.verbose > 0):
        print("         Color: %d (%s)" % (oleBlock["color"], "Black" if oleBlock["color"] else "Red"))
        print("   Prev Dir ID: %s" % ("None" if (oleBlock["PDID"] == config.OLE_NONE_BLOCK) else str(oleBlock["PDID"])))
        print("   Next Dir ID: %s" % ("None" if (oleBlock["NDID"] == config.OLE_NONE_BLOCK) else str(oleBlock["NDID"])))
        print("   Sub  Dir ID: %s" % ("None" if (oleBlock["SDID"] == config.OLE_NONE_BLOCK) else str(oleBlock["SDID"])))
        print("      Class ID: " + oleBlock["CID"])
        print("    User Flags: " + oleBlock["userflags"])
        print("        Create: " + getFormattedWinToPyTimeUTC(oleBlock["create"]))
        print("        Modify: " + getFormattedWinToPyTimeUTC(oleBlock["modify"]))
        print("       1st Sec: %d" % oleBlock["SID_firstSecDir"])
        print("          Size: %d" % oleBlock["SID_sizeDir"])
    return


def printDBHead(thumbType, formatVer, strFormatType, cacheType, strCacheType, cacheOff1st, cacheOff1stAvail, cacheCount):
    print("     Signature: %s" % config.THUMBS_FILE_TYPES[thumbType])
    if (thumbType == config.THUMBS_TYPE_CMMM):
        print("        Format: %d (%s)" % (formatVer, strFormatType))
        print("          Type: %d (%s)" % (cacheType, strCacheType))
        if (config.ARGS.verbose > 0):
            print("    Cache Info:")
            print("          Offset: %s" % ("None" if (cacheOff1st == None) else ("%d" % cacheOff1st)))
            print("   1st Available: %s" % ("None" if (cacheOff1stAvail == None) else ("%d" % cacheOff1stAvail)))
            print("           Count: %s" % ("None" if (cacheCount == None) else ("%d" % cacheCount)))
    elif (thumbType == config.THUMBS_TYPE_IMMM):
        print("        Format: %d (%s)" % (formatVer, strFormatType))
        if (config.ARGS.verbose > 0):
            print("    Entry Info:")
            print("            Used: %s" % ("None" if (cacheOff1st == None) else ("%d" % cacheOff1st)))
            print("           Count: %s" % ("None" if (cacheCount == None) else ("%d" % cacheCount)))
    return


def printDBCache(iCounter, strSig, iSize, strHash, strExt, iIdSize, iPadSize, iDataSize, iWidth, iHeight, iChkSumD, iChkSumH, strID, dictESEDB):
    print(" Entry Counter: %d" % iCounter)
    print("     Signature: %s" % strSig)
    if (config.ARGS.verbose > 0):
        print("          Size: %d" % iSize)
        print("          Hash: %s" % strHash)
        print("     Extension: %s" % strExt)
        print("       ID Size: %d" % iIdSize)
        print("      Pad Size: %d" % iPadSize)
        print("     Data Size: %d" % iDataSize)
        print("  Image  Width: %d" % iWidth)
        print("  Image Height: %d" % iHeight)
        print(" Data Checksum: %d" % iChkSumD)
        print(" Head Checksum: %d" % iChkSumH)
    print("            ID: %s" % strID)
    if (config.ARGS.edbfile != None):
        printESEDBInfo(dictESEDB)
    return


def processESEDBInfo(recordESEDB, strKey, bRaw = False):
    strESEDB = None
    rawESEDB = None
    dataESEDB = None
    iCol = config.ESEDB_ICOL[strKey]
    if (iCol != None):
        cTest = config.ESEDB_ICOL_NAMES[strKey][1]
        # Format the key's value for output...
        # 'x' - bstr  == (Large) Binary Data
        # 's' - str   == (Large) Text
        # 'i' - int   == Integer (32/16/8)-bit (un)signed
        # 'b' - bool  == Boolean or Boolean Flags (Integer)
        # 'f' - float == Floating Point (Double Precision) (64/32-bit)
        # 'd' - date  == Binary Data converted to Formatted UTC Time
        if not bRaw:
            dataESEDB = recordESEDB[strKey]

        if   (cTest == 'x'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data(iCol)
            else:
                strESEDB = str( hexlify( dataESEDB ))[2:-1]  # ...stript off start b' and end '
        elif (cTest == 's'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data_as_string(iCol)
            else:
                strESEDB = dataESEDB
        elif (cTest == 'i'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data_as_integer(iCol)
            else:
                strESEDB = format(dataESEDB, "d")
        elif (cTest == 'b'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data_as_integer(iCol)
                if (rawESEDB == None or rawESEDB == 0):  # ...convert integer to boolean False
                    rawESEDB = False
                elif (rawESEDB == 1 or rawESEDB == -1):  # ...convert integer to boolean True
                    rawESEDB = True
                else:  # Setup Flag Display for integer flags
                    if (rawESEDB < -2147483648):     # ...convert negative 64 bit integer to positive
                        rawESEDB = rawESEDB & 0xffffffffffffffff
                    if (rawESEDB < -32768):          # ...convert negative 32 bit integer to positive
                        rawESEDB = rawESEDB & 0xffffffff
                    if (rawESEDB < -128):            # ...convert negative 16 bit integer to positive
                        rawESEDB = rawESEDB & 0xffff
                    if (rawESEDB < 0):               # ...convert negative 8 bit integer to positive
                        rawESEDB = rawESEDB & 0xff
            else:
                if (isinstance(dataESEDB, bool)):
                    strESEDB = format(dataESEDB, "")
                else:  # ..Integer
                    strFmt = "08b"               # ...setup flag format for 8 bit integer
                    if (dataESEDB > 255):
                        strFmt = "016b"          # ...setup flag format for 16 bit integer format
                    if (dataESEDB > 65535):
                        strFmt = "032b"          # ...setup flag format for 32 bit integer format
                    if (dataESEDB > 4294967295):
                        strFmt = "064b"          # ...setup flag format for 64 bit integer format
                    strESEDB = format(dataESEDB, strFmt)
        elif (cTest == 'f'):
            if bRaw:
                rawESEDB = recordESEDB.get_value_data_as_floating_point(iCol)
            else:
                strESEDB = format(dataESEDB, "G")
        elif (cTest == 'd'):
            if bRaw:
                rawESEDB = unpack("<Q", recordESEDB.get_value_data(iCol))[0]
            else:
                strESEDB = getFormattedWinToPyTimeUTC(dataESEDB)
    if bRaw:
        return rawESEDB
    else:
        return strESEDB


def printESEDBInfo(dictESEDB, bHead = True):
    strEnhance = " ESEBD Enhance:"
    # If there is no output...
    if (config.ESEDB_FILE == None or dictESEDB == None):
        if bHead:
            print(strEnhance + " None")
        return

    # Otherwise, print...
    if bHead:
        print(strEnhance)
    if (config.ARGS.verbose > 0):
        for strKey in config.ESEDB_ICOL_NAMES:
            strESEDB = processESEDBInfo(dictESEDB, strKey)
            if (strESEDB != None):
                print("%s%s" % (config.ESEDB_ICOL_NAMES[strKey][2], strESEDB))
    else:
        strESEDB = processESEDBInfo(dictESEDB, "TCID")
        print("%s%s" % (config.ESEDB_ICOL_NAMES["TCID"][2], strESEDB))
    return

def setupSymLink():
    if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
        if not os.path.exists(config.ARGS.outdir + config.THUMBS_SUBDIR):
            try:
                os.mkdir(config.ARGS.outdir + config.THUMBS_SUBDIR)
            except EnvironmentError:
                sys.stderr.write(" Error: Cannot create %s\n" % config.ARGS.outdir + config.THUMBS_SUBDIR)
                config.EXIT_CODE = 13
                return
    return


def symlink_force(strTarget, strLink):
    try:
        os.symlink(strTarget, strLink)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(strLink)
            os.symlink(strTarget, strLink)
        else:
            sys.stderr.write(" Error: Cannot create symlink %s to file %s\n" % (strLink, strTarget))
            config.EXIT_CODE = 18
            return
    return


def prepareESEDB():
    try:
        from vinetto.lib import pyesedb
        bEDBFileGood = True
    except:
        # Hard Error!  The "pyesedb" library is installed locally with Vinetto,
        #   so missing "pyesedb" library is bad!
        sys.stderr.write(" Error: Cannot import local library pyesedb\n")
        config.EXIT_CODE = 19
        return False

    pyesedb_ver = pyesedb.get_version()
    if (config.ARGS.verbose > 0):
        sys.stderr.write(" Info: Imported pyesedb version %s\n" % pyesedb_ver)

    config.ESEDB_FILE = pyesedb.file()

    # Open ESEBD file...
    try:
        config.ESEDB_FILE.open(config.ARGS.edbfile)
    except IOError:
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: Cannot opened ESEDB File for enhanced processing\n")
        return False

    if (config.ARGS.verbose > 0):
        sys.stderr.write(" Info: Opened ESEDB file %s\n" % config.ARGS.edbfile)

#    # TEST Get Tables...
#    iTblCnt = config.ESEDB_FILE.get_number_of_tables()
#    sys.stderr.write(" DBG: Got %d tables\n" % iTblCnt)
#    for iTbl in range(iTblCnt):
#        table = config.ESEDB_FILE.get_table(iTbl)
#        if (table == None):
#            sys.stderr.write(" DBG:   Table %d is None\n" % iTbl)
#            continue
#        strTblName = table.get_name()
#        sys.stderr.write(" DBG:   Table %d Name %s\n" % (iTbl, strTblName))

    strSysIndex = "SystemIndex_"
    strTableName = "PropertyStore"
    config.ESEDB_TABLE = config.ESEDB_FILE.get_table_by_name(strSysIndex + strTableName)
    if (config.ESEDB_TABLE == None):  # ...try older table name...
        strTableName = "0A"
        config.ESEDB_TABLE = config.ESEDB_FILE.get_table_by_name(strSysIndex + strTableName)
    if (config.ESEDB_TABLE == None):  # ...still no table available?...
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: Cannot opened ESEDB Table for enhanced processing\n")
        return False

    if (config.ARGS.verbose > 0):
        sys.stderr.write(" Info: Opened ESEDB Table %s%s for enhanced processing\n" % (strSysIndex, strTableName))

    iColCnt = config.ESEDB_TABLE.get_number_of_columns()
    if (config.ARGS.verbose > 1):
        sys.stderr.write(" Info:     Got %d columns\n" % iColCnt)
    iColCntFound = 0
    for iCol in range(iColCnt):
        column = config.ESEDB_TABLE.get_column(iCol)
        strColName = column.get_name()
        for strKey in config.ESEDB_ICOL_NAMES:
            if (strColName.endswith(config.ESEDB_ICOL_NAMES[strKey][0])):
                config.ESEDB_ICOL[strKey] = iCol  # ...column number for column name
                iColCntFound += 1

        if (iColCntFound == len(config.ESEDB_ICOL_NAMES)):  # Total Columns searched
            break

    if (not config.ARGS.quiet):
        sys.stderr.write(" INFO:        ESEDB %d columns of %d possible\n" % (iColCntFound, len(config.ESEDB_ICOL_NAMES)))

    return True


def loadESEDB():
    if (config.ESEDB_ICOL["TCID"] == None):
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: No ESEDB Image column %s available\n" % ESEDB_ICOL_NAMES["TCID"][0])
        return False
    if (config.ESEDB_ICOL["MIME"] == None and config.ESEDB_ICOL["CTYPE"] == None and config.ESEDB_ICOL["ITT"] == None):
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: No ESEDB Image columns %s available\n" %
                             (ESEDB_ICOL_NAMES["MIME"][0] + ", " +
                              ESEDB_ICOL_NAMES["CTYPE"][0] + ", or " +
                              ESEDB_ICOL_NAMES["ITT"][0]))
        return False

    config.ESEDB_REC_LIST = []

    iRecCnt = config.ESEDB_TABLE.get_number_of_records()
    strRecIPD = None
    strRecIU = None
    for iRec in range(iRecCnt):
        record = config.ESEDB_TABLE.get_record(iRec)

        # Test for ThumbnailCacheId exists...
        bstrRecTCID = record.get_value_data(config.ESEDB_ICOL["TCID"])
        if (bstrRecTCID == None):
            continue

        # Test for image type record...
        strMime = ""
        if (config.ESEDB_ICOL["MIME"] != None):
            strMime = (record.get_value_data_as_string(config.ESEDB_ICOL["MIME"]) or "")
        strCType = ""
        if (config.ESEDB_ICOL["CTYPE"] != None):
            strCType = (record.get_value_data_as_string(config.ESEDB_ICOL["CTYPE"]) or "")
        strITT = ""
        if (config.ESEDB_ICOL["ITT"] != None):
            strITT = (record.get_value_data_as_string(config.ESEDB_ICOL["ITT"]) or "")
        strImageTest = strMime + strCType + strITT
        if (not "image" in strImageTest):
            continue

#        # TEST Record Retrieval...
#        print("\nTCID: " + str( hexlify( bstrRecTCID ))[2:-1])
#        for strKey in config.ESEDB_ICOL_NAMES:
#            if (strKey == "TCID"):
#                continue
#            sys.stdout.write(strKey + ": ")
#            rawESEDB = processESEDBInfo(record, strKey, True)
#            print(rawESEDB)

        dictRecord = {}
        dictRecord["TCID"]  = bstrRecTCID
        dictRecord["MIME"]  = strMime
        dictRecord["CTYPE"] = strCType
        dictRecord["ITT"]   = strITT

        for strKey in config.ESEDB_ICOL_NAMES:
            if (strKey == "TCID" or strKey == "MIME" or strKey == "CTYPE" or strKey == "ITT"):
                continue
            dictRecord[strKey] = processESEDBInfo(record, strKey, True)

        config.ESEDB_REC_LIST.append(dictRecord)

#    # TEST: Print ESEDB Image Records...
#    for dictRecord in config.ESEDB_REC_LIST:
#        printESEDBInfo(dictRecord, False)
#        print()

    if (len(config.ESEDB_REC_LIST) == 0):
        config.ESEDB_REC_LIST = None
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: No ESEDB Image data available\n")
        return False

    if (not config.ARGS.quiet):
        sys.stderr.write(" INFO:        ESEDB Image data loaded\n")

    return True


def examineESEBDRecord(strCmd):
    strValidRecord = "Enter a valid record number"

    print("List Record")
    if (strCmd[2:] == ""):
        print(strValidRecord)
    else:
        iVerboseOld = config.ARGS.verbose
        config.ARGS.verbose = 1

        try:
            iRec = int(strCmd[2:])
            try:
                dictRecord = config.ESEDB_REC_LIST[iRec - 1]
                print("Record: %d" % iRec)
                printESEDBInfo(dictRecord, False)
                print()
            except:
                print(strValidRecord)
        except:
            print(strValidRecord)

        config.ARGS.verbose = iVerboseOld

    return


def examineESEBD():
    import re
    import readline

    try:
        funcInput = raw_input
    except NameError:
        funcInput = input

    def prompt(strMessage, strErrorMessage, isValid):
        # Prompt for input given a message and return that value after verifying the input.
        #
        # Keyword arguments:
        #   strMessage -- the message to display when asking the user for the value
        #   strErrorMessage -- the message to display when the value fails validation
        #   isValid -- a function that returns True if the value given by the user is valid

        res = None
        while res is None:
            res = funcInput(str(strMessage)+' > ')
            if (not isValid(res)):
                print(str(strErrorMessage))
                res = None
        return res

    strValidColumn = "Enter a valid column number"
    strRecordsFound = "Records Found: %d\n"
    strMessage = "ESEDB Explorer"
    strErrorMessage = "A valid command must be provided. Try 'h'."
    while (True):
        strCmd = prompt(
            strMessage,
            strErrorMessage,
            isValid = lambda v : re.search(r"^[ehlqs]$|^l .+$", v))

        if (strCmd == "h"):  # Help
            print("Help")
            print("Available Commands:")
            print("  h - this help")
            print("  l - list all stored ESEDB data")
            print("  l record - list the specified ESEDB record verbose")
            print("  s - search stored ESEDB data")
            print("  e - exit (quit) ESEDB Explorer")
            print("  q - exit (quit) ESEDB Explorer")

        elif (strCmd == "l"):  # List
            print("List")
            iCount = 0
            for dictRecord in config.ESEDB_REC_LIST:
                iCount += 1
                print("Record: %d" % iCount)
                printESEDBInfo(dictRecord, False)
                print()
            print(strRecordsFound % iCount)

        elif (strCmd[:2] == "l "):  # List Record
            examineESEBDRecord(strCmd)

        elif (strCmd == "s"):  # Search
            strColKey = None
            iCol = None
            strRegEx = None

            while (True):
                strCmd = prompt(
                    (strMessage + ": Search " + ( "All Columns" if (strColKey == None) else ("Column %d (%s)" % (iCol, strColKey)) )),
                    strErrorMessage,
                    isValid = lambda v : re.search(r"^[ehlq]$|^[clv] .*$", v))

                if (strCmd == "h"):  # Help
                    print("Help")
                    print("Available Commands:")
                    print("  h - this help")
                    print("  l - list all searchable columns")
                    print("  l record - list the specified ESEDB record verbose")
                    print("  c column - select specified column number (blank for all)")
                    print("  v regex - search for value matching regex in selected column")
                    print("  e - exit (quit) Search")
                    print("  q - exit (quit) Search")

                elif (strCmd == "l"):  # List
                    print("List")
                    for strKey in config.ESEDB_ICOL:
                        print("% 4d : %6s  %s" % (config.ESEDB_ICOL[strKey], strKey, config.ESEDB_ICOL_NAMES[strKey][0]))

                elif (strCmd[:2] == "l "):  # List Record
                    examineESEBDRecord(strCmd)

                elif (strCmd[:2] == "c "):  # Column Selection
                    print("Column Selection")
                    if (strCmd[2:] == ""):
                        strColKey = None
                        iCol = None
                    else:
                        try:
                            iColNew = int(strCmd[2:])
                            try:
                                strColKey = list(config.ESEDB_ICOL.keys())[list(config.ESEDB_ICOL.values()).index(iColNew)]
                                iCol = iColNew
                            except:
                                print("Enter a valid column number")
                        except:
                            print("Enter a valid column number")

                elif (strCmd[:2] == "v "):  # Value RegEx
                    print("Searching columns in records...")
                    iCount = 0
                    iRec = 0
                    if (strCmd[2:] == ""):
                        strRegEx = None
                    else:
                        strRegEx = strCmd[2:]
                        reObj = re.compile(strRegEx)
                        isFound = lambda v : reObj.search(v) if (v != None) else False
                        for dictRecord in config.ESEDB_REC_LIST:
                            iRec += 1
                            bFound = False
                            if (strColKey == None):
                                for strKey in dictRecord:
                                    if isFound(processESEDBInfo(dictRecord, strKey)):
                                        bFound = True
                                        break
                            elif isFound(processESEDBInfo(dictRecord, strColKey)):
                                bFound = True

                            if (bFound):
                                iCount += 1
                                print("Record: %d" % iRec)
                                printESEDBInfo(dictRecord)
                                print()
                    print(strRecordsFound % iCount)

                elif (strCmd == "e" or strCmd == "q"):  # Exit/Quit
                    break

                else:
                    print(strErrorMessage)

        elif (strCmd == "e" or strCmd == "q"):  # Exit/Quit
            break

        else:
            print(strErrorMessage)

    del readline
    del re
    return


def searchEDB(strTCID):
    if (config.ESEDB_REC_LIST == None or strTCID == None):
        return None

    strConvertTCID = strTCID
    if (len(strTCID)%2 == 1):
        strConvertTCID = "0" + strTCID
    try:
        bstrTCID = unhexlify(strConvertTCID)
    except:
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: Cannot unhex given Thumbnail Cache ID (%s) for compare\n" % strConvertTCID)
        return None

    bFound = False
    for dictRecord in config.ESEDB_REC_LIST:
#        # TEST TCID Compare...
#        print(str(hexlify(bstrTCID))[2:-1] + " <> " + str(hexlify(dictRecord["BTCID"]))[2:-1])
        if (bstrTCID == dictRecord["TCID"]):
            bFound = True
            break

    if (not bFound):
        return None

    return dictRecord


def processThumbsTypeOLE(infile, thumbsDB, thumbsDBsize):
    global HTTP_REPORT
    global IMAGE_TYPE_1_HEADER, IMAGE_TYPE_1_QUANTIZE, IMAGE_TYPE_1_HUFFMAN

    if (not config.ARGS.quiet):
        if (thumbsDBsize % 512 ) != 0:
            sys.stderr.write(" Warning: Length of %s == %d not multiple 512\n" % (infile, thumbsDBsize))

    tDB_endian = "<"  # Little Endian

    # Structure:
    # --------------------
    # The CFBF file consists of a 512-Byte header record followed by a number of
    # sectors whose size is defined in the header. The literature defines Sectors
    # to be either 512 or 4096 bytes in length, although the format is potentially
    # capable of supporting sectors ranging in size from 128-Bytes upwards in
    # powers of 2 (128, 256, 512, 1024, etc.). The lower limit of 128 is the
    # minimum required to fit a single directory entry in a Directory Sector.
    #
    # There are several types of sector that may be present in a CFBF:
    #
    # * Sector Allocation Table (FAT) Sector - contains chains of sector indices
    #     much as a FAT does in the FAT/FAT32 filesystems
    # * MiniSAT Sectors - similar to the SAT but storing chains of mini-sectors
    #     within the Mini-Stream
    # * Double-Indirect SAT (DISAT) Sector - contains chains of SAT sector indices
    # * Directory Sector – contains directory entries
    # * Stream Sector – contains arbitrary file data
    # * Range Lock Sector – contains the byte-range locking area of a large file

    thumbsDB.seek(8)  # ...skip magic bytes                              # File Signature: 0xD0CF11E0A1B11AE1 for current version
    tDB_GUID              = thumbsDB.read(16)                            # CLSID
    tDB_revisionNo        = unpack(tDB_endian+"H", thumbsDB.read(2))[0]  # Minor Version
    tDB_versionNo         = unpack(tDB_endian+"H", thumbsDB.read(2))[0]  # Version
    tDB_endianOrder       = thumbsDB.read(2)  # 0xFFFE OR 0xFEFF         # Byte Order, 0xFFFE (Intel)

    if (tDB_endianOrder == bytearray(b"\xff\xfe")):
        tDB_endian = ">"  # Big Endian
    #elif (tDB_endianOrder == bytearray(b"\xfe\xff")):
    #    tDB_endian = "<"
    tDB_sectorSize        = unpack(tDB_endian+"H", thumbsDB.read(2))[0]  # Sector Shift
    tDB_sectorSizeMini    = unpack(tDB_endian+"H", thumbsDB.read(2))[0]  # Mini Sector Shift
    reserved              = unpack(tDB_endian+"H", thumbsDB.read(2))[0]  # short int reserved
    reserved              = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # int reserved
    reserved              = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # Sector Count for Directory Chain (4 KB Sectors)
    tDB_SID_totalSecSAT   = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # Sector Count for SAT Chain (512 B Sectors)
    tDB_SID_firstSecDir   = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # Root Directory: 1st Sector in Directory Chain
    reserved              = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # Signature for transactions (0, not implemented)
    tDB_streamMinSize     = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # Mini Stream Max Size (typically 4 KB)
    tDB_SID_firstSecMSAT  = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # First Sector in the MiniSAT chain
    tDB_SID_totalSecMSAT  = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # Sector Count in the MiniSAT chain
    tDB_SID_firstSecDISAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # First Sector in the DISAT chain
    tDB_SID_totalSecDISAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # Sector Count in the DISAT chain

    # Load Sector Allocation Table (SAT) list...
    listSAT = []
    for iCurrentSector in range(tDB_SID_totalSecSAT):
        iOffset = 76 + (iCurrentSector * 4)
        thumbsDB.seek(iOffset)
        listSAT.append(unpack(tDB_endian+"L", thumbsDB.read(4))[0])

    # Load Mini Sector Allocation Table (MniSAT) list...
    iCurrentSector = tDB_SID_firstSecMSAT
    listMiniSAT = []
    while (iCurrentSector != config.OLE_LAST_BLOCK):
        listMiniSAT.append(iCurrentSector)
        iCurrentSector = nextBlock(thumbsDB, listSAT, iCurrentSector, tDB_endian)

    iCurrentSector = tDB_SID_firstSecDir
    iOffset = 512 + iCurrentSector * 512

    # Load Mini SAT Streams list...
    thumbsDB.seek(iOffset + 116)
    iStream = unpack(tDB_endian+"L", thumbsDB.read(4))[0]  # First Mini SAT Stream
    listMiniSATStreams = []
    while (iStream != config.OLE_LAST_BLOCK):
        listMiniSATStreams.append(iStream)
        iStream = nextBlock(thumbsDB, listSAT, iStream, tDB_endian)

    # =============================================================
    # Process Entries...
    # =============================================================

    tdbStreams = tdb_streams.TDB_Streams()
    tdbCatalog = tdb_catalog.TDB_Catalog()

    iStreamCounter = 0
    while (iCurrentSector != config.OLE_LAST_BLOCK):
        iOffset = 512 + iCurrentSector * 512
        for i in range(iOffset, iOffset + 512, 128):  # 4 Entries per Block: 128 * 4 = 512
            thumbsDB.seek(i)
            oleBlock = {}
            oleBlock["nameDir"]         = thumbsDB.read(64)
            oleBlock["nameDirSize"]     = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
            oleBlock["type"]            = unpack("B",            thumbsDB.read(1))[0]
            oleBlock["color"]           = unpack("?",            thumbsDB.read(1))[0]
            oleBlock["PDID"]            = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
            oleBlock["NDID"]            = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
            oleBlock["SDID"]            = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
            oleBlock["CID"]             = str(hexlify( thumbsDB.read(16) ))[2:-1]
            oleBlock["userflags"]       = str(hexlify( thumbsDB.read( 4) ))[2:-1]
            oleBlock["create"]          = unpack(tDB_endian+"Q", thumbsDB.read(8))[0]
            oleBlock["modify"]          = unpack(tDB_endian+"Q", thumbsDB.read(8))[0]
            oleBlock["SID_firstSecDir"] = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
            oleBlock["SID_sizeDir"]     = unpack(tDB_endian+"L", thumbsDB.read(4))[0]

            # Convert encoded bytes to unicode string:
            #   a unicode string length is half the bytes length minus 1 (terminal null)
            strRawName = decodeBytes(oleBlock["nameDir"])[0:(oleBlock["nameDirSize"] // 2 - 1)]

            # Empty Entry processing...
            # =============================================================
            if (oleBlock["type"] == 0):
                if (not config.ARGS.quiet):
                    print(" Empty Entry\n" +
                          " --------------------")
                    printBlock(strRawName, oleBlock)
                    print(STR_SEP)

            # Storage Entry processing...
            # =============================================================
            elif (oleBlock["type"] == 1):
                if (not config.ARGS.quiet):
                    print(" Storage Entry\n" +
                          " --------------------")
                    printBlock(strRawName, oleBlock)
                    print(STR_SEP)

            # Stream Entry processing...
            # =============================================================
            elif (oleBlock["type"] == 2):
                bRegularBlock = (oleBlock["SID_sizeDir"] >= 4096)

                if (not config.ARGS.quiet):
                    print(" Stream Entry (" + ("Standard" if bRegularBlock else "Mini") + ")\n" +
                          " --------------------")
                    printBlock(strRawName, oleBlock)

                #strStreamID  = "%04d" % iStreamCounter
                strStreamID = strRawName[::-1]  # ...reverse the raw name
                keyStreamName = strRawName
                bHasSymName = False
                iStreamID = -1
                if (len(strStreamID) < 4):
                    try:
                        iStreamID = int(strStreamID)
                    except ValueError:
                        iStreamID = -1
                if (iStreamID >= 0):
                    #strStreamID = "%04d" % iStreamID
                    bHasSymName = True
                    keyStreamName = iStreamID

                if (config.EXIT_CODE > 0):
                    return

                bytesToWrite = oleBlock["SID_sizeDir"]
                sr = bytearray(b"")

                if (bRegularBlock):  # ...stream located in the SAT...
                    iCurrentStreamBlock = oleBlock["SID_firstSecDir"]
                    while (iCurrentStreamBlock != config.OLE_LAST_BLOCK):
                        iStreamOffset = 512 + iCurrentStreamBlock * 512
                        thumbsDB.seek(iStreamOffset)

                        if (bytesToWrite >= 512):
                            sr = sr + thumbsDB.read(512)
                        else:
                            sr = sr + thumbsDB.read(bytesToWrite)
                        bytesToWrite = bytesToWrite - 512
                        iCurrentStreamBlock = nextBlock(thumbsDB, listSAT, iCurrentStreamBlock, tDB_endian)

                else:  # ...stream located in the Mini SAT...
                    iCurrentStreamMiniBlock = oleBlock["SID_firstSecDir"]
                    while (iCurrentStreamMiniBlock != config.OLE_LAST_BLOCK):
                        # Computing offset of the miniBlock to copy
                        # 1 : Which block of the Mini SAT stream?
                        nb = iCurrentStreamMiniBlock // 8
                        # 2 : Where is this block?
                        bl = listMiniSATStreams[nb]
                        # 3 : Which offset from the start of block?
                        ioffset = (iCurrentStreamMiniBlock % 8) * 64

                        iStreamOffset = 512 + bl * 512 + ioffset
                        thumbsDB.seek(iStreamOffset)

                        if (bytesToWrite >= 64):
                            sr = sr + thumbsDB.read(64)
                        else:
                            sr = sr + thumbsDB.read(bytesToWrite)
                        bytesToWrite = bytesToWrite - 64
                        # Computing next iCurrentStreamMiniBlock
                        iCurrentStreamMiniBlock = nextBlock(thumbsDB, listMiniSAT, iCurrentStreamMiniBlock, tDB_endian)

                sr_len = len(sr)

                # Catalog Stream processing...
                # -------------------------------------------------------------
                if (strRawName == "Catalog"):
                    if (not config.ARGS.quiet):
                        print("       Entries: ---------------------------------------")

                    # Get catalog header...
                    iCatOffset      = unpack(tDB_endian+"H", sr[ 0: 2])[0]
                    iCatVersion     = unpack(tDB_endian+"H", sr[ 2: 4])[0]
                    iCatThumbCount  = unpack(tDB_endian+"L", sr[ 4: 8])[0]
                    iCatThumbWidth  = unpack(tDB_endian+"L", sr[ 8:12])[0]
                    iCatThumbHeight = unpack(tDB_endian+"L", sr[12:16])[0]

                    iStreamCounter -= 1

                    # Process catalog entries...
                    while (iCatOffset < sr_len):
                        # Preamble...
                        iCatEntryLen       = unpack(tDB_endian+"L", sr[iCatOffset      :iCatOffset +  4])[0]
                        iCatEntryID        = unpack(tDB_endian+"L", sr[iCatOffset +  4 :iCatOffset +  8])[0]
                        iCatEntryTimestamp = unpack(tDB_endian+"Q", sr[iCatOffset +  8 :iCatOffset + 16])[0]
                        # The Catalog Entry Name:
                        # 1. starts after the preamable (16)
                        # 2. end with 4 null bytes (4)
                        # Therefore, the start of the name string is at the end of the preamble
                        #   and the end of the name string is at the end of the entry minus 4
                        bstrCatEntryName   =                        sr[iCatOffset + 16: iCatOffset + iCatEntryLen - 4]

                        strCatEntryId        = "%d" % (iCatEntryID)
                        strCatEntryTimestamp = getFormattedWinToPyTimeUTC(iCatEntryTimestamp)
                        strCatEntryName      = decodeBytes(bstrCatEntryName)
                        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                            strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strCatEntryId + ".jpg"
                            symlink_force(strTarget, config.ARGS.outdir + strCatEntryName)
                            if (config.EXIT_CODE > 0):
                                return
                        if (not config.ARGS.quiet):
                            print("          " + ("% 4s" % strCatEntryId) + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strCatEntryName)
                        tdbCatalog[iCatEntryID] = (strCatEntryTimestamp, strCatEntryName)

                        # Next catalog entry...
                        iCatOffset = iCatOffset + iCatEntryLen

                # Image Stream processing...
                # -------------------------------------------------------------
                else:
                    # Is End Of Image (EOI) at end of stream?
                    if (sr[sr_len - 2: sr_len] != bytearray(b"\xff\xd9")):  # ...Not End Of Image (EOI)
                        sys.stderr.write(" Error: Missing End of Image (EOI) marker in stream %d\n" % iStreamCounter)
                        config.EXIT_CODE = 14
                        return

                    # --- Header 1: Get file offset...
                    headOffset   = unpack(tDB_endian+"L", sr[ 0: 4])[0]
                    headRevision = unpack(tDB_endian+"L", sr[ 4: 8])[0]

                    # Is length OK?
                    if (unpack(tDB_endian+"H", sr[ 8:10])[0] != (sr_len - headOffset)):
                        sys.stderr.write(" Error: Header 1 length mismatch in stream %d\n" % iStreamCounter)
                        config.EXIT_CODE = 15
                        return

                    strExt = "jpg"
                    if (len(strRawName) >= 4):
                        # ESEDB Search...
                        dictESEDB = searchEDB(strRawName[strRawName.find("_") + 1: ])
                        if (dictESEDB != None):
                            if (not config.ARGS.quiet):
                                printESEDBInfo(dictESEDB)
                            if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                                if (dictESEDB["IURL"] != None):
                                    strFileName = dictESEDB["IURL"].split("/")[-1].split("?")[0]
                                    strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strRawName + "." + strExt
                                    symlink_force(strTarget, config.ARGS.outdir + strFileName)
                                    if (config.EXIT_CODE > 0):
                                        return
                                    fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_URLS, "a+")
                                    fileURL.write(strTarget + " => " + strFileName + "\n")
                                    fileURL.close()

                    # --- Header 2: Type 2 Thumbnail Image? (Full JPEG)...
                    if (sr[headOffset: headOffset + 4] == bytearray(b"\xff\xd8\xff\xe0")):
                        if (config.ARGS.outdir != None):
                            strFileName = tdbStreams.getFileName(keyStreamName, strExt, bHasSymName, 2)
                            fileImg = open(config.ARGS.outdir + strFileName, "wb")
                            fileImg.write(sr[headOffset:])
                            fileImg.close()
                        else:  # Not extracting...
                            tdbStreams[keyStreamName] = ["", (2, "")]

                    # --- Header 2: Type 1 Thumbnail Image? (Partial JPEG)...
                    elif (unpack(tDB_endian+"L", sr[headOffset: headOffset + 4])[0] == 1):
                        # Is second header OK?
                        if (unpack(tDB_endian+"H", sr[headOffset + 4: headOffset + 6])[0] != (sr_len - headOffset - 16)):
                            sys.stderr.write(" Error: Header 2 length mismatch in stream %d\n" % iStreamCounter)
                            config.EXIT_CODE = 16
                            return

                        if (config.ARGS.outdir != None and PIL_FOUND):
                            strFileName = tdbStreams.getFileName(keyStreamName, strExt, bHasSymName, 1)

                            # Construct thumbnail image from standard blocks and stored image data...
                            bstrImage = ( IMAGE_TYPE_1_HEADER[:20] +
                                          IMAGE_TYPE_1_QUANTIZE + sr[30:52] +
                                          IMAGE_TYPE_1_HUFFMAN  + sr[52:] )

                            image = Image.open(StringIO.StringIO(bstrImage))
                            #r, g, b, a = image.split()
                            #image = Image.merge("RGB", (r, g, b))
                            image = image.transpose(Image.FLIP_TOP_BOTTOM)
                            image.save(config.ARGS.outdir + strFileName, "JPEG", quality=100)
                        else:  # Cannot extract (PIL not found) or not extracting...
                            tdbStreams[keyStreamName] = ["", (1, "")]
                    else:
                        sys.stderr.write(" Error: Header 2 not found in stream %d\n" % iStreamCounter)
                        config.EXIT_CODE = 17
                        return

                if (not config.ARGS.quiet):
                    print(STR_SEP)

            # Lock Bytes Entry processing...
            # =============================================================
            elif (oleBlock["type"] == 3):
                if (not config.ARGS.quiet):
                    print(" Lock Bytes Entry\n" +
                          " --------------------")
                    printBlock(strRawName, oleBlock)
                    print(STR_SEP)

            # Property Entry processing...
            # =============================================================
            elif (oleBlock["type"] == 4):
                if (not config.ARGS.quiet):
                    print(" Property Entry\n" +
                          " --------------------")
                    printBlock(strRawName, oleBlock)
                    print(STR_SEP)

            # Root Entry processing...
            # =============================================================
            elif (oleBlock["type"] == 5):
                if (not config.ARGS.quiet):
                    print(" Root Entry\n" +
                          " --------------------")
                    printBlock(strRawName, oleBlock)
                    print(STR_SEP)
                if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
                    HTTP_REPORT.setOLE(oleBlock)

            iStreamCounter += 1

        iCurrentSector = nextBlock(thumbsDB, listSAT, iCurrentSector, tDB_endian)

    # Process end of file...
    # -----------------------------------------------------------------
    if (config.ARGS.verbose > 0):
        if (tdbCatalog.isOutOfSequence()):
            sys.stderr.write(" Info: %s - Catalog index number out of usual sequence\n" % infile)

    if (config.ARGS.verbose > 0):
        if (tdbStreams.isOutOfSequence()):
            sys.stderr.write(" Info: %s - Stream index number out of usual sequence\n" % infile)

    astrStats = tdbStreams.extractStats()

    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")

    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
          strSubDir = config.THUMBS_SUBDIR
        HTTP_REPORT.flush(astrStats, strSubDir, tdbStreams, tdbCatalog)

    if (not config.ARGS.quiet):
        if (len(tdbCatalog) > 0):
            if (tdbCatalog.getCount() != tdbStreams.getCount()):
                sys.stderr.write(" Warning: %s - Counts (Catalog != Extracted)\n" % infile)
            else:
                if (config.ARGS.verbose > 0):
                    sys.stderr.write(" Info: %s - Counts (Catalog == Extracted)\n" % infile)
        else:
            if (config.ARGS.verbose > 0):
                sys.stderr.write(" Info: %s - No Catalog\n" % infile)


def processThumbsTypeCMMM(infile, thumbsDB, thumbsDBsize):
    global HTTP_REPORT

    # tDB_endian = "<" ALWAYS Little???

    if (thumbsDBsize < 24):
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: %s too small to process header\n" % infile)
        return

    # Header...
    thumbsDB.seek(4)
    tDB_formatVer        = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheType        = unpack("<L", thumbsDB.read(4))[0]
    if (tDB_formatVer > config.TC_FORMAT_TYPE.get("Windows 8")):
        thumbsDB.read(4)  # Skip an integer size
    tDB_cacheOff1st      = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheOff1stAvail = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheCount       = None  # Cache Count not available above Windows 8 v2
    if (tDB_formatVer < config.TC_FORMAT_TYPE.get("Windows 8 v3")):
        tDB_cacheCount   = unpack("<L", thumbsDB.read(4))[0]

    try:
        strFormatType = list(config.TC_FORMAT_TYPE.keys())[list(config.TC_FORMAT_TYPE.values()).index(tDB_formatVer)]
    except ValueError:
        strFormatType = "Unknown Format"
    try:
        strCacheType = ("thumbcache_" +
                        config.TC_CACHE_TYPE[config.TC_FORMAT_TO_CACHE[tDB_formatVer]][tDB_cacheType] +
                        ".db")
    except (KeyError, IndexError):
        strCacheType = "Unknown Type"

    if (not config.ARGS.quiet):
        print(" Header\n --------------------")
        printDBHead(config.THUMBS_TYPE_CMMM, tDB_formatVer, strFormatType, tDB_cacheType, strCacheType,
                    tDB_cacheOff1st, tDB_cacheOff1stAvail, tDB_cacheCount)
        print(STR_SEP)
    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        HTTP_REPORT.setCMMM(strFormatType, strCacheType, tDB_cacheOff1st, tDB_cacheOff1stAvail, tDB_cacheCount)

    # =============================================================
    # Process Cache Entries...
    # =============================================================

    tdbStreams = tdb_streams.TDB_Streams()
    tdbCatalog = tdb_catalog.TDB_Catalog()

    iOffset = tDB_cacheOff1st
    iCacheCounter = 1
    while (True):
        if (thumbsDBsize < (iOffset + 48)):
            if (not config.ARGS.quiet):
                sys.stderr.write(" Warning: Remaining cache entry %d too small to process\n" % iCacheCounter)
            break

        thumbsDB.seek(iOffset)
        tDB_sig = thumbsDB.read(4)
        if (tDB_sig != config.THUMBS_SIG_CMMM):
            break
        tDB_size = unpack("<L", thumbsDB.read(4))[0]
        tDB_hash = unpack("<Q", thumbsDB.read(8))[0]
        iOffset += 16

        tDB_ext = None  # File Extension not available above Windows Vista
        if (tDB_formatVer == config.TC_FORMAT_TYPE.get("Windows Vista")):
            tDB_ext = thumbsDB.read(8)  # 2 bytes * 4 wchar_t characters
            iOffset += 8

        tDB_idSize   = unpack("<L",  thumbsDB.read(4))[0]
        tDB_padSize  = unpack("<L",  thumbsDB.read(4))[0]
        tDB_dataSize = unpack("<L",  thumbsDB.read(4))[0]
        iOffset += 12

        tDB_width  = None  # Image Width  not available below Windows 8
        tDB_height = None  # Image Height not available below Windows 8
        if (tDB_formatVer > config.TC_FORMAT_TYPE.get("Windows 7")):
            tDB_width  = unpack("<L",  thumbsDB.read(4))[0]
            tDB_height = unpack("<L",  thumbsDB.read(4))[0]
            iOffset += 8

        reserved     = unpack("<L",  thumbsDB.read(4))[0]
        tDB_chksumD  = unpack("<Q",  thumbsDB.read(8))[0]
        tDB_chksumH  = unpack("<Q",  thumbsDB.read(8))[0]
        iOffset += 20

        tDB_id = None
        if (tDB_idSize > 0):
            tDB_id   = thumbsDB.read(tDB_idSize)
        tDB_pad = None
        if (tDB_padSize > 0):
            tDB_pad  = thumbsDB.read(tDB_padSize)
        tDB_data = None
        if (tDB_dataSize > 0):
            tDB_data = thumbsDB.read(tDB_dataSize)

        iOffset += (tDB_idSize + tDB_padSize + tDB_dataSize)

        strID = None
        if (tDB_id != None):
            strID = decodeBytes(tDB_id)
        else:
            continue  # ...no ID, so probably empty last entry

        strHash = format(tDB_hash, 'x')

        strExt = None
        # Try the given Vista ext...
        if (tDB_ext != None):
            strExt = decodeBytes(tDB_ext)
        if (tDB_dataSize > 0):
            # Detect data type ext by magic bytes...
            tupleImageTypes = (
                    ( bytearray(b'\x42\x4D'), "bmp" ),                         # BM
                    ( bytearray(b'\xFF\xD8\xFF\xE0'), "jpg" ),                 # ....
                    ( bytearray(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'), "png" )  # .PNG\n\r\sub\r
                )
            for tupleImageType in tupleImageTypes:
                if (tupleImageType[0] == tDB_data[0:len(tupleImageType[0])]):
                    strExt = tupleImageType[1]

            # If there still is no ext, use a neutral default ".img"...
            if (strExt == None):
                strExt = "img"
        # Otherwise,
        #    No Data, no Ext!

        # ESEDB Search...
        dictESEDB = searchEDB(strID)

        if (not config.ARGS.quiet):
            print(" Cache Entry\n --------------------")
            printDBCache(iCacheCounter, tDB_sig.decode(), tDB_size, strHash, strExt, tDB_idSize, tDB_padSize, tDB_dataSize,
                         tDB_width, tDB_height, tDB_chksumD, tDB_chksumH, strID, dictESEDB)

        strCleanFileName = cleanFileName(strID)
        bHasSymName = False

        if (tDB_dataSize > 0):
            # Setup symbolic link to filename...
            if (dictESEDB != None and dictESEDB["TCID"] != None):
                strFileName = None
                if (dictESEDB["IURL"] != None):
                    strFileName = dictESEDB["IURL"].split("/")[-1].split("?")[0]
                if (strFileName != None and config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                        bHasSymName = True
                        strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strCleanFileName + "." + strExt
                        symlink_force(strTarget, config.ARGS.outdir + strFileName)
                        if (config.EXIT_CODE > 0):
                                return
                        fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_URLS, "a+")
                        fileURL.write(strTarget + " => " + strFileName + "\n")
                        fileURL.close()

                # Add a "catalog" entry...
                tdbCatalog[iCacheCounter] = (getFormattedWinToPyTimeUTC(dictESEDB["DATEM"]), strFileName)

            # Write data to filename...
            if (config.ARGS.outdir != None):
                strFileName = tdbStreams.getFileName(strCleanFileName, strExt, bHasSymName, 2)
                fileImg = open(config.ARGS.outdir + strFileName, "wb")
                fileImg.write(tDB_data)
                fileImg.close()
            else:  # Not extracting...
                tdbStreams[strID] = ["", (2, "")]

        # End of Loop
        iCacheCounter += 1

        if (not config.ARGS.quiet):
            print(STR_SEP)

        # Check End of File...
        if (thumbsDBsize <= iOffset):
            break

    astrStats = tdbStreams.extractStats()
    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
          strSubDir = config.THUMBS_SUBDIR
        HTTP_REPORT.flush(astrStats, strSubDir, tdbStreams, tdbCatalog)


def processThumbsTypeIMMM(infile, thumbsDB, thumbsDBsize):
    global HTTP_REPORT

    # tDB_endian = "<" ALWAYS

    if (thumbsDBsize < 24):
        if (not config.ARGS.quiet):
            sys.stderr.write(" Warning: %s too small to process header\n" % infile)
        return

    # Header...
    tDB_formatVer  = unpack("<l", thumbsDB[ 4: 8])[0]
    reserved       = unpack("<l", thumbsDB[ 8:12])[0]
    tDB_entryUsed  = unpack("<l", thumbsDB[12:16])[0]
    tDB_entryCount = unpack("<l", thumbsDB[16:20])[0]
    reserved       = unpack("<l", thumbsDB[20:24])[0]

    try:
        strFormatType = list(config.TC_FORMAT_TYPE.keys())[list(config.TC_FORMAT_TYPE.values()).index(tDB_formatVer)]
    except ValueError:
        strFormatType = "Unknown Format"

    if (not config.ARGS.quiet):
        print(" Header\n --------------------")
        printDBHead(config.THUMBS_TYPE_IMMM, tDB_formatVer, strFormatType, None, None,
                    tDB_entryUsed, None, tDB_entryCount)
        print(STR_SEP)
    if (config.ARGS.htmlrep):
        HTTP_REPORT.setIMMM(strFormatType, tDB_entryUsed, tDB_entryCount)

    # Cache...
    iOffset = 24
    iEntryCounter = 1
    while (iEntryCounter < tDB_entryCount):
        if (thumbsDBsize < (iOffset + 32)):
            if (not config.ARGS.quiet):
                sys.stderr.write(" Warning: %s too small to process cache entry %d\n" % (infile, iCacheCounter))
            return

        tDB_hash = unpack("<Q", thumbsDB[iOffset +  0: iOffset + 8])[0]

        iOffFlags = iOffset + 8
        if (tDB_formatVer == config.TC_FORMAT_TYPE.get("Windows Vista")):
            tDB_filetime = unpack("<Q", thumbsDB[iOffFlags: iOffFlags + 8])[0]
            iOffFlags += 8

        tDB_flags   = unpack("<l", thumbsDB[iOffFlags +  0: iOffFlags +  4])[0]
        tDB_tc_32   = unpack("<l", thumbsDB[iOffFlags +  4: iOffFlags +  8])[0]
        tDB_tc_96   = unpack("<l", thumbsDB[iOffFlags +  8: iOffFlags + 12])[0]
        tDB_tc_256  = unpack("<l", thumbsDB[iOffFlags + 12: iOffFlags + 16])[0]
        tDB_tc_1024 = unpack("<l", thumbsDB[iOffFlags + 16: iOffFlags + 20])[0]
        tDB_tc_sr   = unpack("<l", thumbsDB[iOffFlags + 20: iOffFlags + 24])[0]

        if (not config.ARGS.quiet):
            print(" Cache Entry %d\n --------------------" % iEntryCounter)

        # TODO: DO MORE!!!

        # End of Loop
        iOffset = iOffFlags + 24
        iEntryCounter += 1

        if (not config.ARGS.quiet):
            print(STR_SEP)

    astrStats = tdbStreams.extractStats()
    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
          strSubDir = config.THUMBS_SUBDIR
        HTTP_REPORT.flush(astrStats, strSubDir)


def processThumbFile(infile, bProcessError=True):
    global HTTP_REPORT


    # Open given Thumbnail file...
    thumbsDBsize = os.stat(infile).st_size
    thumbsDB = open(infile,"rb")

    # Get MD5 of Thumbs.db file...
    thumbsDBmd5 = None
    if (config.ARGS.md5force) or ((not config.ARGS.md5never) and (thumbsDBsize < (1024 ** 2) * 512)):
        try:
            # Python >= 2.5
            from hashlib import md5
            thumbsDBmd5 = md5(thumbsDB.read()).hexdigest()
        except:
            # Python < 2.5
            import md5
            thumbsDBmd5 = md5.new(thumbsDB.read()).hexdigest()
        del md5

    # -----------------------------------------------------------------------------
    # Begin analysis output...

    if (not config.ARGS.quiet):
        print(STR_SEP)
        print(" File: %s" % infile)
        if (thumbsDBmd5 != None):
            print("  MD5: %s" % thumbsDBmd5)
        print(STR_SEP)

    # -----------------------------------------------------------------------------
    # Analyzing header block...

    thumbsDBtype = None
    thumbsDB.seek(0)
    thumbsDBdata = thumbsDB.read(8)
    if   (thumbsDBdata[0:8] == config.THUMBS_SIG_OLE):
        thumbsDBtype = config.THUMBS_TYPE_OLE
    elif (thumbsDBdata[0:8] == config.THUMBS_SIG_OLEB):
        thumbsDBtype = config.THUMBS_TYPE_OLE
    elif (thumbsDBdata[0:4] == config.THUMBS_SIG_CMMM):
        thumbsDBtype = config.THUMBS_TYPE_CMMM
    elif (thumbsDBdata[0:4] == config.THUMBS_SIG_IMMM):
        thumbsDBtype = config.THUMBS_TYPE_IMMM
    else:  # ...Header Signature not found...
        if (bProcessError):
            sys.stderr.write(" Error: Header Signature not found in %s\n" % infile)
            config.EXIT_CODE = 12
        return  # ..always return

    # Initialize optional HTML report...
    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        HTTP_REPORT = report.HtmlReport(getEncoding(), infile, config.ARGS.outdir,
                                        thumbsDBtype, thumbsDBsize, thumbsDBmd5)

    if (thumbsDBtype == config.THUMBS_TYPE_OLE):
        processThumbsTypeOLE(infile, thumbsDB, thumbsDBsize)
    elif (thumbsDBtype == config.THUMBS_TYPE_CMMM):
        processThumbsTypeCMMM(infile, thumbsDB, thumbsDBsize)
    elif (thumbsDBtype == config.THUMBS_TYPE_IMMM):
        processThumbsTypeIMMM(infile, thumbsDB, thumbsDBsize)
    else:  # ...should never hit this as thumbsDBtype is set in prior "if" block above,
          # ...thumbsDBtype should always be set properly
        if (bProcessError):
            sys.stderr.write(" Error: No process for Header Signature in %s\n" % infile)
            config.EXIT_CODE = 12

    return


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
        processThumbFile(thumbFile, False)

    return


def processRecursiveDirectory():
    # Walk the directories from given directory recursively down...
    for dirpath, dirnames, filenames in os.walk(config.ARGS.infile):
        processDirectory(dirpath, filenames)
    return


def processFileSystem():
    #
    # Process well known Thumb Cache DB files with ESE DB enhancement (if available)
    #

    strUserBaseDirVista = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_VISTA)
    strUserBaseDirXP = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_XP)
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
    elif os.path.isdir(strUserBaseDirXP):
        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info: FS - Detected a Windows XP-like partition, processing all user subdirectories\n")
        # For XP, only process each User's subdirectories...
        with os.scandir(strUserBaseDirXP) as iterDirs:
            for entryUserDir in iterDirs:
                if not entryUserDir.is_dir():
                    continue
                processDirectory(entryUserDir)
    else:
        if (config.ARGS.verbose > 0):
            sys.stderr.write(" Info: FS - Generic partition, processing all subdirectories (recursive operating mode)\n")
        processDirectory(config.ARGS.infile)

    return


# ================================================================================
#
# Beginning ...
#
# ================================================================================

def main():
    global IMAGE_TYPE_1_HEADER, IMAGE_TYPE_1_QUANTIZE, IMAGE_TYPE_1_HUFFMAN

    config.ARGS = getArgs()

    strError = " Error: "

    # Test Input File parameter...
    if (config.ARGS.infile != None):
        if not os.path.exists(config.ARGS.infile):  # ...NOT exists?
            sys.stderr.write("%s%s does not exist\n" % (strError, config.ARGS.infile))
            sys.exit(10)
        if (config.ARGS.mode == "f"):  # Traditional Mode...
            if not os.path.isfile(config.ARGS.infile):  # ...NOT a file?
                sys.stderr.write("%s%s not a file\n" % (strError, config.ARGS.infile))
                sys.exit(10)
        else:  # Directory, Recursive Directory, or Automatic Mode...
            if not os.path.isdir(config.ARGS.infile):  # ...NOT a directory?
                sys.stderr.write("%s%s not a directory\n" % (strError, config.ARGS.infile))
                sys.exit(10)
            # Add ending '/' as needed...
            if not config.ARGS.infile.endswith('/'):
                config.ARGS.infile += "/"
        if not os.access(config.ARGS.infile, os.R_OK):  # ...NOT readable?
            sys.stderr.write("%s%s not readable\n" % (strError, config.ARGS.infile))
            sys.exit(10)

    # Test Output Directory parameter...
    if (config.ARGS.outdir != None):
        if not os.path.exists(config.ARGS.outdir):  # ...NOT exists?
            try:
                os.mkdir(config.ARGS.outdir)  # ...make it
                if (config.ARGS.verbose > 0):
                    sys.stderr.write(" Info: %s was created\n" % config.ARGS.outdir)
            except EnvironmentError as e:
                sys.stderr.write("%sCannot create %s\n" % (strError, config.ARGS.outdir))
                sys.exit(11)
        else:  # ...exists...
            if not os.path.isdir(config.ARGS.outdir):  # ...NOT a directory?
                sys.stderr.write("%s%s is not a directory\n" % (strError, config.ARGS.outdir))
                sys.exit(11)
            elif not os.access(config.ARGS.outdir, os.W_OK):  # ...NOT writable?
                sys.stderr.write("%s%s not writable\n" % (strError, config.ARGS.outdir))
                sys.exit(11)
        # Add ending '/' as needed...
        if not config.ARGS.outdir.endswith('/'):
            config.ARGS.outdir += "/"

        # Remove existing URL file...
        if os.path.exists(config.ARGS.outdir + config.THUMBS_FILE_URLS):
            os.remove(config.ARGS.outdir + config.THUMBS_FILE_URLS)

    # Correct QUIET mode...
    if (config.ARGS.quiet) and (config.ARGS.verbose > 0):
        config.ARGS.quiet = False

    # Correct MD5 mode...
    if (config.ARGS.md5force) and (config.ARGS.md5never):
        config.ARGS.md5force = False

    # Test EDB File parameter...
    bEDBErrorOut = True
    bEDBFileGood = False
    strEDBFileReport = config.ARGS.edbfile
    strErrorReport = strError
    if (config.ARGS.mode == "a" and config.ARGS.edbfile == None):
        bEDBErrorOut = False
        strErrorReport = " Warning: "
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
            if bEDBErrorOut: sys.exit(19)
        elif not os.path.isfile(config.ARGS.edbfile):  # ...NOT a file?
            if (bEDBErrorOut or not config.ARGS.quiet):
                sys.stderr.write("%s%s is not a file\n" % (strErrorReport, strEDBFileReport))
            if bEDBErrorOut: sys.exit(19)
        elif not os.access(config.ARGS.edbfile, os.R_OK):  # ...NOT readable?
            if (bEDBErrorOut or not config.ARGS.quiet):
                sys.stderr.write("%s%s not readable\n" % (strErrorReport, strEDBFileReport))
            if bEDBErrorOut: sys.exit(19)

        bEDBFileGood = prepareESEDB()
        if (config.EXIT_CODE == 0):
            if bEDBFileGood:  # ...ESEBD good?...
                bEDBFileGood = loadESEDB()
            if not bEDBFileGood:  # ...ESEBD bad?...
                if (not config.ARGS.quiet):
                    sys.stderr.write(" Warning: Skipping ESEDB enhanced processing\n")
        if (config.ESEDB_FILE != None):
            config.ESEDB_TABLE = None
            config.ESEDB_FILE.close()

    if (config.EXIT_CODE == 0):
        # Initialize processing for output...
        if (config.ARGS.outdir != None):

            # Initializing PIL library for Type 1 image extraction...
            PIL_FOUND = True
            try:
                from PIL import Image
            except ImportError:
                PIL_FOUND = False
                if (not config.ARGS.quiet):
                    sys.stderr.write(" Warning: Cannot find PIL Package Image module.\n" +
                                     "          Vinetto will only extract Type 2 thumbnails.\n")
            if (PIL_FOUND == True):
                IMAGE_TYPE_1_HEADER   = open(resource_filename("vinetto", "data/header"), "rb").read()
                IMAGE_TYPE_1_QUANTIZE = open(resource_filename("vinetto", "data/quantization"), "rb").read()
                IMAGE_TYPE_1_HUFFMAN  = open(resource_filename("vinetto", "data/huffman"), "rb").read()

            # Initializing Symbolic (soft) File Links...
            setupSymLink()

    if (config.EXIT_CODE == 0):
        if (config.ARGS.infile == None and config.ARGS.edbfile != None):
            examineESEBD()
        elif (config.ARGS.mode == "f"):  # Traditional Mode
            processThumbFile(config.ARGS.infile)
        elif (config.ARGS.mode == "d"):  # Directory Mode
            processDirectory(config.ARGS.infile)
        elif (config.ARGS.mode == "r"):  # Recursive Directory Mode
            processRecursiveDirectory()
        elif (config.ARGS.mode == "a"):  # Automatic Mode - File System
            processFileSystem()
        else:  # Unknown Mode - should never occur
            sys.stderr.write("%sUnknown mode (%s) to process %s\n" % (strError, config.ARGS.mode, config.ARGS.infile))
            config.EXIT_CODE = 10

    if (config.EXIT_CODE > 0):
        sys.exit(config.EXIT_CODE)
