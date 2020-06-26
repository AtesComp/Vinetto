# -*- coding: UTF-8 -*-
"""
module thumbCMMM.py
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
from __future__ import print_function


file_major = "0"
file_minor = "1"
file_micro = "10"


import sys
from io import StringIO
from struct import unpack

try:
    import vinetto.config as config
    import vinetto.esedb as esedb
    import vinetto.tdb_catalog as tdb_catalog
    import vinetto.tdb_streams as tdb_streams
    import vinetto.utils as utils
except ImportError:
    import config
    import esedb
    import tdb_catalog
    import tdb_streams
    import utils


def printHead(dictCMMMMeta):
    print("     Signature: %s" % config.THUMBS_FILE_TYPES[config.THUMBS_TYPE_CMMM])
    print("        Format: %d (%s)" % (dictCMMMMeta["FormatType"], dictCMMMMeta["FormatTypeStr"]))
    print("          Type: %d (%s)" % (dictCMMMMeta["CacheType"], dictCMMMMeta["CacheTypeStr"]))
    if (config.ARGS.verbose > 0):
        print("    Cache Info:")
        print("          Offset: %s" % str(dictCMMMMeta["CacheOff1st"]))
        print("   1st Available: %s" % str(dictCMMMMeta["CacheOff1stAvail"]))
        print("           Count: %s" % str(dictCMMMMeta["CacheCount"]))
    return


def printCache(strSig, iSize, strHash, strExt, iIdSize, iPadSize, iDataSize, iWidth, iHeight, iChkSumD, iChkSumH, keyStreamName):
    print("     Signature: %s" % strSig)
    if (config.ARGS.verbose > 0):
        print("          Size: %s" % str(iSize))
        print("          Hash: %s" % str(strHash))
        print("     Extension: %s" % str(strExt))
        print("       ID Size: %s" % str(iIdSize))
        print("      Pad Size: %s" % str(iPadSize))
        print("     Data Size: %s" % str(iDataSize))
        print("  Image  Width: %s" % str(iWidth))
        print("  Image Height: %s" % str(iHeight))
        print(" Data Checksum: %s" % str(iChkSumD))
        print(" Head Checksum: %s" % str(iChkSumH))
    print("            ID: %s" % keyStreamName)
    if (config.ARGS.verbose > 0):
        if (config.ARGS.edbfile != None):
            config.ESEDB.printInfo()
    return


def process(infile, fileThumbsDB, iThumbsDBSize):
    # tDB_endian = "<" ALWAYS Little???

    if (iThumbsDBSize < 24):
        if (config.ARGS.verbose >= 0):
            sys.stderr.write(" Warning: %s too small to process header\n" % infile)
        return

    # Header...
    dictCMMMMeta = {}
    fileThumbsDB.seek(4)

    dictCMMMMeta["FormatType"]       = unpack("<L", fileThumbsDB.read(4))[0]
    dictCMMMMeta["FormatTypeStr"]    = "Unknown Format"
    try:
        dictCMMMMeta["FormatTypeStr"] = list(config.TC_FORMAT_TYPE.keys())[list(config.TC_FORMAT_TYPE.values()).index(dictCMMMMeta["FormatType"])]
    except:
        pass

    dictCMMMMeta["CacheType"]        = unpack("<L", fileThumbsDB.read(4))[0]
    dictCMMMMeta["CacheTypeStr"] = "Unknown Type"
    try:
        dictCMMMMeta["CacheTypeStr"] = ("thumbcache_" +
                        config.TC_CACHE_TYPE[config.TC_FORMAT_TO_CACHE[dictCMMMMeta["FormatType"]]][dictCMMMMeta["CacheType"]] +
                        ".db")
    except:
        pass

    if (dictCMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 8")):
        reserved01 = fileThumbsDB.read(4)  # Skip an integer size

    dictCMMMMeta["CacheOff1st"]      = unpack("<L", fileThumbsDB.read(4))[0]
    dictCMMMMeta["CacheOff1stAvail"] = unpack("<L", fileThumbsDB.read(4))[0]
    dictCMMMMeta["CacheCount"]       = None  # Cache Count not available above Windows 8 v2
    if (dictCMMMMeta["FormatType"] < config.TC_FORMAT_TYPE.get("Windows 8 v3")):
        dictCMMMMeta["CacheCount"]   = unpack("<L", fileThumbsDB.read(4))[0]


    if (config.ARGS.verbose >= 0):
        print(" Header\n --------------------")
        printHead(dictCMMMMeta)
        print(config.STR_SEP)

    if (config.ARGS.htmlrep):  # ...implies config.ARGS.outdir
        config.HTTP_REPORT.setCMMM(dictCMMMMeta)

    # =============================================================
    # Process Cache Entries...
    # =============================================================

    tdbStreams = tdb_streams.TDB_Streams()
    tdbCatalog = tdb_catalog.TDB_Catalog()

    iOffset = dictCMMMMeta["CacheOff1st"]
    iCacheCounter = 1
    while (True):
        if (iThumbsDBSize < (iOffset + 48)):
            if (config.ARGS.verbose >= 0):
                sys.stderr.write(" Warning: Remaining cache entry %d too small to process\n" % iCacheCounter)
            break

        fileThumbsDB.seek(iOffset)
        tDB_sig = fileThumbsDB.read(4)
        if (tDB_sig != config.THUMBS_SIG_CMMM):
            break
        tDB_size = unpack("<L", fileThumbsDB.read(4))[0]
        tDB_hash = unpack("<Q", fileThumbsDB.read(8))[0]
        iOffset += 16

        tDB_ext = None  # File Extension not available above Windows Vista
        if (dictCMMMMeta["FormatType"] == config.TC_FORMAT_TYPE.get("Windows Vista")):
            tDB_ext = fileThumbsDB.read(8)  # 2 bytes * 4 wchar_t characters
            iOffset += 8

        tDB_idSize   = unpack("<L",  fileThumbsDB.read(4))[0]
        tDB_padSize  = unpack("<L",  fileThumbsDB.read(4))[0]
        tDB_dataSize = unpack("<L",  fileThumbsDB.read(4))[0]
        iOffset += 12

        tDB_width  = None  # Image Width  not available below Windows 8
        tDB_height = None  # Image Height not available below Windows 8
        if (dictCMMMMeta["FormatType"] > config.TC_FORMAT_TYPE.get("Windows 7")):
            tDB_width  = unpack("<L",  fileThumbsDB.read(4))[0]
            tDB_height = unpack("<L",  fileThumbsDB.read(4))[0]
            iOffset += 8

        reserved02   = unpack("<L",  fileThumbsDB.read(4))[0]
        tDB_chksumD  = unpack("<Q",  fileThumbsDB.read(8))[0]
        tDB_chksumH  = unpack("<Q",  fileThumbsDB.read(8))[0]
        iOffset += 20

        tDB_id = None
        if (tDB_idSize > 0):
            tDB_id   = fileThumbsDB.read(tDB_idSize)
        tDB_pad = None
        if (tDB_padSize > 0):
            tDB_pad  = fileThumbsDB.read(tDB_padSize)
        tDB_data = None
        if (tDB_dataSize > 0):
            tDB_data = fileThumbsDB.read(tDB_dataSize)

        iOffset += (tDB_idSize + tDB_padSize + tDB_dataSize)

        # Set default Stream Name key to add to Thumb DB Streams (tdbStreams) dict...
        #   Key may be str or int
        keyStreamName = None
        if (tDB_id != None):
            keyStreamName = utils.decodeBytes(tDB_id)
        else:
            continue  # ...no ID, so probably empty last entry

        strHash = format(tDB_hash, 'x')

        strExt = None
        # Try the given Vista ext...
        if (tDB_ext != None):
            strExt = utils.decodeBytes(tDB_ext)
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

        if (config.ARGS.verbose >= 0):
            print(" Cache Entry %d\n --------------------" % iCacheCounter)
            printCache(tDB_sig.decode(), tDB_size, strHash, strExt, tDB_idSize, tDB_padSize, tDB_dataSize,
                         tDB_width, tDB_height, tDB_chksumD, tDB_chksumH, keyStreamName)

        strCleanFileName = utils.cleanFileName(keyStreamName)

        if (tDB_dataSize > 0):
            strFileName = None
            if (config.ARGS.edbfile != None):
                # ESEDB Search...
                isESEDBRecFound = config.ESEDB.search(keyStreamName)
                if (isESEDBRecFound):
                    strCatEntryTimestamp = utils.getFormattedWinToPyTimeUTC(config.ESEDB.dictRecord["DATEM"])
                    if (config.ESEDB.dictRecord["IURL"] != None):
                        strFileName = config.ESEDB.dictRecord["IURL"].split("/")[-1].split("?")[0]

            if (strFileName != None):
                # Setup symbolic link to filename...
                if (config.ARGS.symlinks):  # ...implies config.ARGS.outdir
                    strTarget = config.THUMBS_SUBDIR + "/" + strCleanFileName + "." + strExt
                    setSymlink(strTarget, config.ARGS.outdir + strFileName)

                    fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_SYMS, "a+")
                    fileURL.write(strTarget + " => " + strFileName + "\n")
                    fileURL.close()

                # Add a "catalog" entry...
                tdbCatalog[strCleanFileName] = (strCatEntryTimestamp, strFileName)

                if (config.ARGS.verbose >= 0):
                    print("  CATALOG " + strCleanFileName + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strFileName)

            # Write data to filename...
            if (config.ARGS.outdir != None):
                strFileName = tdbStreams.getFileName(strCleanFileName, strExt)
                fileImg = open(config.ARGS.outdir + strFileName, "wb")
                fileImg.write(tDB_data)
                fileImg.close()
            else:  # Not extracting...
                tdbStreams[strCleanFileName] = config.LIST_PLACEHOLDER

        # End of Loop
        iCacheCounter += 1

        if (config.ARGS.verbose >= 0):
            print(config.STR_SEP)

        # Check End of File...
        if (iThumbsDBSize <= iOffset):
            break

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
        config.HTTP_REPORT.flush(astrStats, strSubDir, tdbStreams, tdbCatalog)
