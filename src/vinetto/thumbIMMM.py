# -*- coding: UTF-8 -*-
"""
module thumbIMMM.py
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
file_micro = "9"


import sys
from struct import unpack

import vinetto.config as config
#import vinetto.tdb_catalog as tdb_catalog
import vinetto.tdb_streams as tdb_streams
import vinetto.utils as utils


def printHead(dictIMMMMeta, iFileSize):
    print("     Signature: %s" % config.THUMBS_FILE_TYPES[config.THUMBS_TYPE_IMMM])
    print("        Format: %d (%s)" % (dictIMMMMeta["FormatType"], dictIMMMMeta["FormatTypeStr"]))
    print("          Size: %d" % iFileSize)
    print("    Entry Info:")
    print("        Reserved: %s" % str(dictIMMMMeta["Reserved01"]))
    print("            Used: %s" % str(dictIMMMMeta["EntryUsed"]))
    print("           Count: %s" % str(dictIMMMMeta["EntryCount"]))
    print("           Total: %s" % str(dictIMMMMeta["EntryTotal"]))
    if (config.ARGS.verbose > 1):
        strUnknown = "Unknown"
        for key in  dictIMMMMeta:
            if strUnknown in key:
                print("      " + strUnknown + " " + key[-2:] + ": " + str(dictIMMMMeta[key]))

    return


def printCache(dictThumbDBEntry):
    strHash = format(dictThumbDBEntry["Hash"], "016x")
    strFlags = format(dictThumbDBEntry["Flags"], "032b")[2:] # bin(dictThumbDBEntry["Flags"][2:]
    print("          Hash: %s" % str(strHash))
    print("        Modify: %s" % utils.getFormattedWinToPyTimeUTC(dictThumbDBEntry["FileTime"]))
    print("         Flags: %s" % str(strFlags))

    if (config.ARGS.verbose < 1):
        return

    iNegOne = config.OLE_NONE_BLOCK  # ...filter out unused values
    if (config.ARGS.verbose > 1):
        iNegOne = None  # ...show unused, i.e., don't filter

    # Check each offset for use (value), unused (-1), or not present (None)
    for iIndex in range( len(config.TC_CACHE_ALL) ):
        key = config.TC_CACHE_ALL[iIndex]
        # Filter uninteresting entries: None == not read from the file
        #                                -1  == cleared
        if (dictThumbDBEntry.get(key) != None and dictThumbDBEntry[key] != iNegOne):
            print("   Offset % 4s: % 11d  [%s]" % (config.TC_CACHE_ALL_DISPLAY[iIndex],
                                                   -1 if dictThumbDBEntry[key] == config.OLE_NONE_BLOCK else dictThumbDBEntry[key],
                                                   format(dictThumbDBEntry[key], "08x")))

    return


def process(infile, fileThumbsDB, iThumbsDBSize, iInitialOffset = 0):
    # tDB_endian = "<" ALWAYS

    if (iThumbsDBSize < 24):
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: %s too small to process header\n" % infile)
        return

    # Setup inital offset...
    iOffset = iInitialOffset + 4

    # Header...
    dictIMMMMeta = {}
    fileThumbsDB.seek(iOffset)

    dictIMMMMeta["FormatType"]       = unpack("<L", fileThumbsDB.read(4))[0]
    dictIMMMMeta["FormatTypeStr"]    = "Unknown Format"
    try:
        dictIMMMMeta["FormatTypeStr"] = list(config.TC_FORMAT_TYPE.keys())[list(config.TC_FORMAT_TYPE.values()).index(dictIMMMMeta["FormatType"])]
    except:
        pass

    dictIMMMMeta["Reserved01"] = unpack("<L", fileThumbsDB.read(4))[0]
    dictIMMMMeta["EntryUsed"]  = unpack("<L", fileThumbsDB.read(4))[0]
    dictIMMMMeta["EntryCount"] = unpack("<L", fileThumbsDB.read(4))[0]
    dictIMMMMeta["EntryTotal"] = unpack("<L", fileThumbsDB.read(4))[0]
    iOffset += 20

    if (dictIMMMMeta["FormatType"] == config.TC_FORMAT_TYPE.get("Windows 10")):
        dictIMMMMeta["Unknown02"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown03"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown04"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown05"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown06"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown07"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown08"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown09"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown10"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown11"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown12"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown13"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown14"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown15"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown16"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown17"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown18"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown19"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown20"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown21"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown22"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown23"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown24"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown25"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown26"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown27"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown28"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown29"] = unpack("<L", fileThumbsDB.read(4))[0]
        dictIMMMMeta["Unknown30"] = unpack("<L", fileThumbsDB.read(4))[0]
        iOffset += 116

    if (config.ARGS.verbose >= 0):
        print(" Header\n --------------------")
        printHead(dictIMMMMeta, iThumbsDBSize)
        print(config.STR_SEP)

    if (config.ARGS.htmlrep):
        config.HTTP_REPORT.setIMMM(dictIMMMMeta)

    # =============================================================
    # Process Cache Entries...
    # =============================================================

    tdbStreams = tdb_streams.TDB_Streams()
    #tdbCatalog = tdb_catalog.TDB_Catalog()

    iCacheCounter = 1
    iPrinted = 0
    while (True):
        if (iThumbsDBSize < (iOffset + 32)):
            if (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: %s too small to process cache entry %d\n" % (infile, iCacheCounter))
            return

        dictThumbDBEntry = {}

        iOffEntry = 0
        fileThumbsDB.seek(iOffset)

        dictThumbDBEntry["Hash"] = unpack("<Q", fileThumbsDB.read(8))[0]
        iOffEntry += 8

        dictThumbDBEntry["FileTime"] = None
        if (dictIMMMMeta["FormatType"] == config.TC_FORMAT_TYPE.get("Windows Vista")):
            dictThumbDBEntry["FileTime"] = unpack("<Q", fileThumbsDB.read(8))[0]
            iOffEntry += 8

        dictThumbDBEntry["Flags"] = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        # Parse the Thumbcache File Offsets...
        # ------------------------------------------------------------
        dictThumbDBEntry["16"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            dictThumbDBEntry["16"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["32"]   = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        dictThumbDBEntry["48"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            dictThumbDBEntry["48"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["96"]   = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        dictThumbDBEntry["256"]  = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        dictThumbDBEntry["768"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            dictThumbDBEntry["768"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["1024"] = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        dictThumbDBEntry["1280"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            dictThumbDBEntry["1280"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["1600"] = None
        if (dictIMMMMeta["FormatType"] == config.TC_FORMAT_TYPE.get("Windows 8.1")):
            dictThumbDBEntry["1600"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["1920"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            dictThumbDBEntry["1920"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["2560"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            dictThumbDBEntry["2560"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["sr"]   = unpack("<L", fileThumbsDB.read(4))[0]
        iOffEntry += 4

        dictThumbDBEntry["wide"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            dictThumbDBEntry["wide"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["exif"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            dictThumbDBEntry["exif"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["wide_alternate"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8 v3")):
            dictThumbDBEntry["wide_alternate"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        dictThumbDBEntry["custom_stream"] = None
        if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8.1")):
            dictThumbDBEntry["custom_stream"] = unpack("<L", fileThumbsDB.read(4))[0]
            iOffEntry += 4

        # Decide how to print the current Cache Entry...
        bPrint = 2  # Full Print (DEFAULT)
        bEmptyOrUnused = (dictThumbDBEntry["Flags"] == 0x0 or dictThumbDBEntry["Flags"] == 0xffffffff)
        bCompleteEmpty = (dictThumbDBEntry["Hash"] == 0x0 and dictThumbDBEntry["Flags"] == 0x0)
        if (config.ARGS.verbose < 0):
            bPrint = 0  # No Print
        elif (config.ARGS.verbose == 0):
            if (bEmptyOrUnused):
                bPrint = 0  # No Print
            # Otherwise, Full Print
        elif (config.ARGS.verbose == 1):
            if (bCompleteEmpty):
                bPrint = 0  # No Print
            elif (bEmptyOrUnused):
                bPrint = 1  # Empty Print
            # Otherwise, Full Print
        elif (config.ARGS.verbose == 2):
            if (bCompleteEmpty):
                bPrint = 1  # Empty Print
            # Otherwise, Full Print
        elif (config.ARGS.verbose > 2):
            bPrint = 2  # Full Print

        if (bPrint):  # ...not 0
            print(" Cache Entry %d\n --------------------" % iCacheCounter)
            if (bPrint == 1):
                print("   Empty!")
            else:  # bPrint > 1
                printCache(dictThumbDBEntry)
            print(config.STR_SEP)
            iPrinted += 1

        # TODO: DO MORE!!!

        # End of Loop
        iCacheCounter += 1

        # Check End of File...
        iOffset += iOffEntry
        #if (dictIMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
        #    if (iOffEntry < 72):
        #        iOffset += (72 - iOffEntry)
        if (iThumbsDBSize <= iOffset):
            break

#    # TEST Print stats on process...
#    print("  Printed: %d,  Offset: %d,  Diff %d" % (iPrinted, iOffset, iThumbsDBSize - iOffset))

    astrStats = tdbStreams.extractStats()
    if (config.ARGS.verbose >= 0):
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
        config.HTTP_REPORT.flush(astrStats, strSubDir)
