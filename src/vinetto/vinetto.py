#!/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
-----------------------------------------------------------------------------

 Vinetto : a forensics tool to examine Thumbs.db files
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
file_micro = "0"


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

from vinetto.utils import addCatalogEntry, countCatalogEntry, countThumbnails, \
                          getStreamFileName, getRawFileName, \
                          isCatalogOutOfSequence, isStreamsOutOfSequence, \
                          addStreamIdToStreams, addFileNameToStreams, \
                          extractStats, convertToPyTime, getFormattedTimeUTC, \
                          cleanFileName

from pkg_resources import resource_filename


IMAGE_TYPE_1_HEADER   = None
IMAGE_TYPE_1_QUANTIZE = None
IMAGE_TYPE_1_HUFFMAN  = None

HTTP_REPORT = None

STR_SEP = " ------------------------------------------------------"


def getArgs():
    # Return arguments passed to vinetto on the command line.

    strProg = os.path.basename(__file__).capitalize()
    strDesc = strProg + " - The Thumbnail File Parser"
    strEpilog = (
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
        "--- " + strProg + " " + version.STR_VERSION + " ---\n" +
        "Based on the original Vinetto by " + version.original_author[0] + "\n" +
        "Author: " + version.author[0] + "\n" +
        strProg + " is open source software\n" +
        "  See: " + version.location
        )

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=strDesc, epilog=strEpilog)
    parser.add_argument("-e", "--edb", dest="edbfile", metavar="EDBFILE",
                        help="examine EDBFILE for original thumbnail filenames")
    parser.add_argument("-H", "--htmlrep", action="store_true", dest="htmlrep",
                        help="write html report to DIR (requires option -o)")
    parser.add_argument("-m", "--mode", dest="mode", choices=["f", "d", "r", "a"], default="f",
                        help=("operating mode: \"f\", \"d\", \"r\", or \"a\"\n" +
                              "  where \"f\" indicates single file processing\n" +
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
                        help="write thumbnails to DIR")
    parser.add_argument("-q", "--quiet", action="store_true", dest="quiet",
                        help="quiet output")
    parser.add_argument("-s", "--symlinks", action="store_true", dest="symlinks",
                        help=("create symlink from the the image realname to the numbered name\n" +
                              "in DIR/" + config.THUMBS_SUBDIR + " (requires option -o)\n" +
                              "NOTE: A Catalog containing the realname must exist for this\n" +
                              "      option to produce results OR a Windows.edb must be given\n" +
                              "      (-e) to find and extract possible file names"))
    parser.add_argument("-U", "--utf8", action="store_true", dest="utf8",
                        help="use utf8 encodings")
    parser.add_argument("--version", action="version", version=strEpilog)
    parser.add_argument("infile",
                        help=("depending on operating mode, either a location to a thumbnail\n" +
                              " file (\"Thumb.db\" or similar) or a directory"))
    pargs = parser.parse_args()

    if (pargs.infile == None):
        parser.error("No input file or directory specified")

    if (pargs.outdir == None):
        if (pargs.htmlrep):
            parser.error("-H option requires -o with a directory name")
        if (pargs.symlinks):
            parser.error("-s option requires -o with a directory name")

    return (pargs)


def getEncoding():
    # What encoding do we use?
    if config.ARGS.utf8:
        return "utf8"
    else:
        return "iso-8859-1"


#def reencodeBytes(bytesString):
#    # Convert bytes encoded as utf-16-le to the global encoding...
#    if (sys.version_info[0] < 3):
#        return unicode(bytesString, "utf-16-le").encode(getEncoding(), "replace")
#    else:
#        return str(bytesString, "utf-16-le").encode(getEncoding(), "replace")


def decodeBytes(bytesString):
    # Convert bytes encoded as utf-16-le to standard unicode...
    if (sys.version_info[0] < 3):
        return unicode(bytesString, "utf-16-le")
    else:
        return str(bytesString, "utf-16-le")


def nextBlock(TDB, Table, indx, endian):
    # Return next block
    iSAT = indx // 128  # SAT block number to search in
    iSECT = indx % 128 # SECTor to search in the SAT block
    iOffset = Table[iSAT] * 512 + 0x200 + iSECT * 4
    TDB.seek(iOffset)
    return unpack(endian+"L", TDB.read(4))[0]


def printBlock(strName, oleBlock):
    print("          Name: %s" % strName)
    print("          Type: %d (%s)" % (oleBlock["type"], config.OLE_BLOCK_TYPES[oleBlock["type"]]))
    print("         Color: %d (%s)" % (oleBlock["color"], "Black" if oleBlock["color"] else "Red"))
    print("   Prev Dir ID: %s" % ("None" if (oleBlock["PDID"] == config.OLE_NONE_BLOCK) else str(oleBlock["PDID"])))
    print("   Next Dir ID: %s" % ("None" if (oleBlock["NDID"] == config.OLE_NONE_BLOCK) else str(oleBlock["NDID"])))
    print("   Sub  Dir ID: %s" % ("None" if (oleBlock["SDID"] == config.OLE_NONE_BLOCK) else str(oleBlock["SDID"])))
    print("      Class ID: " + oleBlock["CID"])
    print("    User Flags: " + oleBlock["userflags"])
    print("        Create: " + oleBlock["create"])
    print("        Modify: " + oleBlock["modify"])
    print("       1st Sec: %d" % oleBlock["SID_firstSecDir"])
    print("          Size: %d" % oleBlock["SID_sizeDir"])
    return


def printDBHead(thumbType, formatVer, strFormatType, cacheType, strCacheType, cacheOff1st, cacheOff1stAvail, cacheCount):
    print("     Signature: %s" % config.THUMBS_FILE_TYPES[thumbType])
    if (thumbType == config.THUMBS_TYPE_CMMM):
        print("        Format: %d (%s)" % (formatVer, strFormatType))
        print("          Type: %d (%s)" % (cacheType, strCacheType))
        print("    Cache Info:")
        print("          Offset: %s" % ("None" if (cacheOff1st == None) else ("%d" % cacheOff1st)))
        print("   1st Available: %s" % ("None" if (cacheOff1stAvail == None) else ("%d" % cacheOff1stAvail)))
        print("           Count: %s" % ("None" if (cacheCount == None) else ("%d" % cacheCount)))
    elif (thumbType == config.THUMBS_TYPE_IMMM):
        print("        Format: %d (%s)" % (formatVer, strFormatType))
        print("    Entry Info:")
        print("            Used: %s" % ("None" if (cacheOff1st == None) else ("%d" % cacheOff1st)))
        print("           Count: %s" % ("None" if (cacheCount == None) else ("%d" % cacheCount)))
    return


def printDBCache(iCounter, strSig, iSize, strHash, strExt, iIdSize, iPadSize, iDataSize, iWidth, iHeight, iChkSumD, iChkSumH, strID, dictESEDB):
    print(" Entry Counter: %d" % iCounter)
    print("     Signature: %s" % strSig)
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
    printESEDBInfo(dictESEDB)
    return


def printESEDBInfo(dictESEDB):
    strEnhance = " ESEBD Enhance:"
    if (config.ESEDB_FILE != None and dictESEDB != None):
        print(strEnhance)

        for strKey in config.ESEDB_ICOL_NAMES.keys():
            iCol = config.ESEDB_ICOL[strKey]
            if (iCol != None):
                print("%s%s" % (config.ESEDB_ICOL_NAMES[strKey][2], dictESEDB[strKey]))
    else:
        print(strEnhance + " None")
    return

def setupSymLink():
    if (config.ARGS.symlinks): # ...implies config.ARGS.outdir
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


def getFileName(iStreamID, strRawName, strExt, bHasSymName, iType):
    strFileName = ""
    if (bHasSymName and config.ARGS.symlinks): # ...implies config.ARGS.outdir
            strFileName = config.THUMBS_SUBDIR + "/"
    if (iStreamID >= 0):
        strFileName += getStreamFileName(iStreamID, strExt, iType)
    else:
        strFileName += getRawFileName(strRawName, strExt, iType)
    return strFileName


def prepareEDB():
    try:
        from vinetto.lib import pyesedb
    except:
        sys.stderr.write(" Error: Cannot import local library pyesedb\n")
        config.EXIT_CODE = 19
        return

    pyesedb_ver = pyesedb.get_version()
    sys.stderr.write(" Info: Imported pyesedb version %s\n" % pyesedb_ver)

    config.ESEDB_FILE = pyesedb.file()

    # Open ESEBD file...
    config.ESEDB_FILE.open(config.ARGS.edbfile)
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
    if (config.ESEDB_TABLE == None): # ...try older...
        strTableName = "0A"
        config.ESEDB_TABLE = config.ESEDB_FILE.get_table_by_name(strSysIndex + strTableName)
    sys.stderr.write(" Info: Opened ESEDB Table %s%s for enhanced processing\n" % (strSysIndex, strTableName))

    iColCnt = config.ESEDB_TABLE.get_number_of_columns()
    sys.stderr.write(" DBG:     Got %d columns\n" % iColCnt)
    iColCntFound = 0
    for iCol in range(iColCnt):
        column = config.ESEDB_TABLE.get_column(iCol)
        strColName = column.get_name()
        for strKey in config.ESEDB_ICOL_NAMES.keys():
            if (strColName.endswith(config.ESEDB_ICOL_NAMES[strKey][0])):
                config.ESEDB_ICOL[strKey] = iCol # ...column number for column name
                iColCntFound += 1

        if (iColCntFound == len(config.ESEDB_ICOL_NAMES)): # Total Columns searched
            break
    sys.stderr.write(" INFO:        ESEDB %d columns of %d possible\n" % (iColCntFound, len(config.ESEDB_ICOL_NAMES)))
    return


def searchEDB(strTCID):
    if (strTCID == None or config.ESEDB_ICOL["TCID"] == None):
        return None

    strConvertTCID = strTCID
    if (len(strTCID)%2 == 1):
        strConvertTCID = "0" + strTCID
    try:
        bstrTCID = unhexlify(strConvertTCID)
    except:
        sys.stderr.write(" Warning: Cannot unhex given Thumbnail Cache ID (%s) for compare\n" % strConvertTCID)
        return None

    iRecCnt = config.ESEDB_TABLE.get_number_of_records()
    strRecIPD = None
    strRecIU = None
    bFound = False
    for iRec in range(iRecCnt):
        record = config.ESEDB_TABLE.get_record(iRec)
        bstrRecTCID = record.get_value_data(config.ESEDB_ICOL["TCID"])
#        # TEST TCID Compare...
#        if (bstrRecTCID != None):
#            print(str(hexlify(bstrTCID))[2:-1] + " <> " + str(hexlify(bstrRecTCID))[2:-1])
#        else:
#            print(str(hexlify(bstrTCID))[2:-1] + " <> " + "None")
        if (bstrRecTCID == None):
            continue
        if (bstrTCID == bstrRecTCID):
            bFound = True
            break

#        # TEST Record Retrieval...
#        strImageTest = ((record.get_value_data_as_string(config.ESEDB_ICOL["MIME"]) or "") +
#                        (record.get_value_data_as_string(config.ESEDB_ICOL["CTYPE"]) or "") +
#                        (record.get_value_data_as_string(config.ESEDB_ICOL["ITT"]) or "") )
#        if ("image" in strImageTest):
#            print("\nTCID: " + str( hexlify( bstrRecTCID ))[2:-1])
#            for strKey in config.ESEDB_ICOL_NAMES.keys():
#                if (strKey == "TCID"):
#                    continue
#                cTest = config.ESEDB_ICOL_NAMES[strKey][1]
#                iCol = config.ESEDB_ICOL[strKey]
#                sys.stdout.write(strKey + ": ")
#                if (iCol != None):
#                    if   (cTest == 'x'):
#                        x = record.get_value_data(iCol)
#                        if (x != None):
#                            x = str(hexlify( x ))[2:-1]
#                    elif (cTest == 's'):
#                        x = record.get_value_data_as_string(iCol)
#                    elif (cTest == 'i'):
#                        x = record.get_value_data_as_integer(iCol)
#                    elif (cTest == 'b'):
#                        iVal = record.get_value_data_as_integer(iCol)
#                        if (iVal == None or iVal == 0):
#                            iVal = False
#                        elif (iVal == 1 or iVal == -1):
#                            iVal = True
#                        else:
#                            strFmt = "08b"
#                            if (iVal > 255):
#                                strFmt = "016b"
#                            if (iVal > 65535):
#                                strFmt = "032b"
#                            if (iVal > 4294967295):
#                                strFmt = "064b"
#                            iVal = format(iVal, strFmt)
#                        x = iVal
#                    elif (cTest == 'f'):
#                        x = record.get_value_data_as_floating_point(iCol)
#                    elif (cTest == 'd'):
#                        x = getFormattedTimeUTC( convertToPyTime( unpack("<Q", record.get_value_data(iCol))[0] ) )
#                    print(x)

    if (not bFound):
        return None

    dictRet = {}
    dictRet["TCID"] = str( hexlify( bstrRecTCID ))[2:-1] # ...stript off start b' and end '

    for strKey in config.ESEDB_ICOL_NAMES.keys():
        if (strKey == "TCID"):
            continue
        cTest = config.ESEDB_ICOL_NAMES[strKey][1]
        iCol = config.ESEDB_ICOL[strKey]
        if (iCol != None):
            # 'x' - bstr  == (Large) Binary Data
            # 's' - str   == (Large) Text
            # 'i' - int   == Integer (32/16/8)-bit (un)signed
            # 'b' - bool  == Boolean or Boolean Flags
            # 'f' - float == Floating Point (Double Precision) (64/32-bit)
            # 'd' - date  == Binary Data converted to Formatted UTC Time
            if   (cTest == 'x'):
                dictRet[strKey] = record.get_value_data(iCol)
            elif (cTest == 's'):
                dictRet[strKey] = record.get_value_data_as_string(iCol)
            elif (cTest == 'i'):
                dictRet[strKey] = record.get_value_data_as_integer(iCol)
            elif (cTest == 'b'):
                iVal = record.get_value_data_as_integer(iCol)
                if (iVal == None or iVal == 0):
                    iVal = False
                elif (iVal == 1 or iVal == -1):
                    iVal = True
                else:
                    if (iVal < -2147483648):
                        iVal = iVal & 0xffffffffffffffff
                    if (iVal < -32768):
                        iVal = iVal & 0xffffffff
                    if (iVal < -128):
                        iVal = iVal & 0xffff
                    if (iVal < 0):
                        iVal = iVal & 0xff
                    strFmt = "08b"
                    if (iVal > 255):
                        strFmt = "016b"
                    if (iVal > 65535):
                        strFmt = "032b"
                    if (iVal > 4294967295):
                        strFmt = "064b"
                iVal = format(iVal, strFmt)
                dictRet[strKey] = iVal
            elif (cTest == 'f'):
                dictRet[strKey] = record.get_value_data_as_floating_point(iCol)
            elif (cTest == 'd'):
                dictRet[strKey] = getFormattedTimeUTC( convertToPyTime( unpack("<Q", record.get_value_data(iCol))[0] ) )

    return dictRet


def processThumbsTypeOLE(infile, thumbsDB, thumbsDBsize):
    global HTTP_REPORT
    global IMAGE_TYPE_1_HEADER, IMAGE_TYPE_1_QUANTIZE, IMAGE_TYPE_1_HUFFMAN

    if (thumbsDBsize % 512 ) != 0:
        sys.stderr.write(" Warning: Length of %s == %d not multiple 512\n" % (infile, thumbsDBsize))

    tDB_endian = "<" # Little Endian

    thumbsDB.seek(0x08)
    tDB_GUID             = thumbsDB.read(16)
    tDB_revisionNo       = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    tDB_versionNo        = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    tDB_endianOrder      = thumbsDB.read(2) # 0xFFFE=65534 OR 0xFEFF=65279

    if (tDB_endianOrder == bytearray(b"\xff\xfe")):
        tDB_endian = ">" # Big Endian
    #elif (tDB_endianOrder == bytearray(b"\xfe\xff")):
    #    tDB_endian = "<"

    tDB_sectorSize       = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    tDB_sectorSizeMini   = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    reserved             = unpack(tDB_endian+"H", thumbsDB.read(2))[0]
    reserved             = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    reserved             = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_totalSecSAT  = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_firstSecDir  = unpack(tDB_endian+"L", thumbsDB.read(4))[0] # Root directory 1st block
    reserved             = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_streamMinSize    = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_firstSecSSAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_totalSecSSAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_firstSecMSAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]
    tDB_SID_totalSecMSAT = unpack(tDB_endian+"L", thumbsDB.read(4))[0]

    SATblocks = []
    for i in range(tDB_SID_totalSecSAT):
        iOffset = 0x4c + (i * 4)
        thumbsDB.seek(iOffset)
        SATblocks.append(unpack(tDB_endian+"L", thumbsDB.read(4))[0])

    # -----------------------------------------------------------------------------
    # Analyzing Root Entry directory ...

    i = tDB_SID_firstSecSSAT
    SSATblocks = []
    while (i != config.OLE_LAST_BLOCK):
        SSATblocks.append(i)
        i = nextBlock(thumbsDB, SATblocks, i, tDB_endian)

    currentBlock = tDB_SID_firstSecDir
    iOffset = 0x200 + currentBlock * 0x200
    thumbsDB.seek(iOffset+0x74)
    firstSSATstreamBlock = unpack(tDB_endian+"L", thumbsDB.read(4))[0]

    i = firstSSATstreamBlock
    SSATstreamBlocks = []
    while (i != config.OLE_LAST_BLOCK):
        SSATstreamBlocks.append(i)
        i = nextBlock(thumbsDB, SATblocks, i, tDB_endian)

    iStreamCounter = 0
    while (currentBlock != config.OLE_LAST_BLOCK):
        iOffset = 0x200 + currentBlock * 0x200
        for i in range(iOffset, iOffset + 0x200, 0x80):
            thumbsDB.seek(i)
            oleBlock["nameDir"]         = thumbsDB.read(0x40)
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

            if (oleBlock["type"] == 2): # stream files extraction
                if (not config.ARGS.quiet):
                    print(" Stream Entry\n --------------------")
                    printBlock(strRawName, oleBlock)

                #strStreamId  = "%04d" % iStreamCounter
                strStreamId = strRawName[::-1] # ...reverse the raw name
                bHasSymName = False
                iStreamID = -1
                if (len(strStreamId) < 4):
                    try:
                        iStreamID = int(strStreamId)
                    except ValueError:
                        iStreamID = -1
                if (iStreamID >= 0):
                    #strStreamId = "%04d" % iStreamID
                    bHasSymName = True

                if (config.EXIT_CODE > 0):
                    return

                bytesToWrite = oleBlock["SID_sizeDir"]
                sr = bytearray(b"")

                if (oleBlock["SID_sizeDir"] >= 4096): # stream located in the SAT
                    currentStreamBlock = oleBlock["SID_firstSecDir"]
                    while (currentStreamBlock != config.OLE_LAST_BLOCK):
                        iStreamOffset = 0x200 + currentStreamBlock * 0x200
                        thumbsDB.seek(iStreamOffset)

                        if (bytesToWrite >= 512):
                            sr = sr + thumbsDB.read(512)
                        else:
                            sr = sr + thumbsDB.read(bytesToWrite)
                        bytesToWrite = bytesToWrite - 512
                        currentStreamBlock = nextBlock(thumbsDB, SATblocks, currentStreamBlock, tDB_endian)

                else:                # stream located in the SSAT
                    currentStreamMiniBlock = oleBlock["SID_firstSecDir"]
                    while (currentStreamMiniBlock != config.OLE_LAST_BLOCK):
                        # Computing offset of the miniBlock to copy
                        # 1 : Which block of the SSATstream?
                        nb = currentStreamMiniBlock // 8
                        # 2 : Where is this block?
                        bl = SSATstreamBlocks[nb]
                        # 3 : Which offset from the start of block?
                        ioffset = (currentStreamMiniBlock % 8) * 64

                        iStreamOffset = 0x200 + bl * 0x200 + ioffset
                        thumbsDB.seek(iStreamOffset)

                        if (bytesToWrite >= 64):
                            sr = sr + thumbsDB.read(64)
                        else:
                            sr = sr + thumbsDB.read(bytesToWrite)
                        bytesToWrite = bytesToWrite - 64
                        # Computing next currentStreamMiniBlock
                        currentStreamMiniBlock = nextBlock(thumbsDB, SSATblocks, currentStreamMiniBlock, tDB_endian)

                # Extraction stream processing ... ---------------------------------

                sr_len = len(sr)

                # Is this a Catalog?
                if (strRawName == "Catalog"):
                    if (not config.ARGS.quiet):
                        print("       Entries: ---------------------------------------")
                    # -------------------------------------------------------------
                    # Catalog header...

                    iCatOffset      = unpack(tDB_endian+"H", sr[ 0: 2])[0]
                    iCatVersion     = unpack(tDB_endian+"H", sr[ 2: 4])[0]
                    iCatThumbCount  = unpack(tDB_endian+"L", sr[ 4: 8])[0]
                    iCatThumbWidth  = unpack(tDB_endian+"L", sr[ 8:12])[0]
                    iCatThumbHeight = unpack(tDB_endian+"L", sr[12:16])[0]

                    iStreamCounter -= 1

                    # -------------------------------------------------------------
                    # Analyzing Catalog entries ...

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
                        iCatEntryName      =                        sr[iCatOffset + 16: iCatOffset + iCatEntryLen - 4]

                        strCatEntryId        = "%d" % (iCatEntryID)
                        strCatEntryTimestamp = getFormattedTimeUTC( convertToPyTime(iCatEntryTimestamp) )
                        strCatEntryName      = decodeBytes(iCatEntryName)
                        if (config.ARGS.symlinks): # ...implies config.ARGS.outdir
                            strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strCatEntryId + ".jpg"
                            symlink_force(strTarget, config.ARGS.outdir + strCatEntryName)
                            if (config.EXIT_CODE > 0):
                                return
                        if (not config.ARGS.quiet):
                            print("          " + ("% 4s" % strCatEntryId) + ":  " + ("%19s" % strCatEntryTimestamp) + "  " + strCatEntryName)
                        addCatalogEntry(iCatEntryID, strCatEntryTimestamp, strCatEntryName)

                        # Next catalog entry...
                        iCatOffset = iCatOffset + iCatEntryLen

                else: # Not a Catalog, an Image entry...
                    # Is EOI at end of stream?
                    if (sr[sr_len - 2: sr_len] != bytearray(b"\xff\xd9")): # ...Not End Of Image (EOI)
                        sys.stderr.write(" Error: Missing End of Image (EOI) marker in stream %d\n" % iStreamCounter)
                        config.EXIT_CODE = 14
                        return

                    # --------------------------- Header 1 ------------------------
                    # Get file offset
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
                        dictESEDB = searchEDB(strRawName[strRawName.find("_")+1:])
                        if (dictESEDB != None):
                            if (not config.ARGS.quiet):
                                printESEDBInfo(dictESEDB)
                            if (config.ARGS.symlinks): # ...implies config.ARGS.outdir
                                if (dictESEDB["IURL"] != None):
                                    strFileName = dictESEDB["IURL"].split("/")[-1].split("?")[0]
                                    strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strRawName + "." + strExt
                                    symlink_force(strTarget, config.ARGS.outdir + strFileName)
                                    if (config.EXIT_CODE > 0):
                                        return
                                    fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_URLS, "a+")
                                    fileURL.write(strTarget + " => " + strFileName + "\n")
                                    fileURL.close()

                    # --------------------------- Header 2 ------------------------
                    # Type 2 Thumbnail Image? (full jpeg)
                    if (sr[headOffset: headOffset + 4] == bytearray(b"\xff\xd8\xff\xe0")):
                        if (config.ARGS.outdir != None):
                            strFileName = getFileName(iStreamID, strRawName, strExt, bHasSymName, 2)
                            fileImg = open(config.ARGS.outdir + strFileName, "wb")
                            fileImg.write(sr[headOffset:])
                            fileImg.close()
                        else: # Not extracting...
                            if (bHasSymName):
                                addStreamIdToStreams(iStreamID, 2, "", "")
                            else:
                                addFileNameToStreams(strRawName, 2, "", "")

                    # Type 1 Thumbnail Image?
                    elif (unpack(tDB_endian+"L", sr[headOffset: headOffset + 4])[0] == 1):
                        # Is second header OK?
                        if (unpack(tDB_endian+"H", sr[headOffset + 4: headOffset + 6])[0] != (sr_len - headOffset - 0x10)):
                            sys.stderr.write(" Error: Header 2 length mismatch in stream %d\n" % iStreamCounter)
                            config.EXIT_CODE = 16
                            return

                        if (config.ARGS.outdir != None and PIL_FOUND):
                            strFileName = getFileName(iStreamID, strRawName, strExt, bHasSymName, 1)
                            # Type 1 Thumbnail Image processing ...
                            type1sr = ( IMAGE_TYPE_1_HEADER[:0x14] +
                                        IMAGE_TYPE_1_QUANTIZE +
                                        sr[0x1e:0x34] +
                                        IMAGE_TYPE_1_HUFFMAN +
                                        sr[0x34:] )

                            image = Image.open(StringIO.StringIO(type1sr))
                            #r, g, b, a = image.split()
                            #image = Image.merge("RGB", (r, g, b))
                            image = image.transpose(Image.FLIP_TOP_BOTTOM)
                            image.save(config.ARGS.outdir + strFileName, "JPEG", quality=100)
                        else: # Cannot extract (PIL not found) or not extracting...
                            if (bHasSymName):
                                addStreamIdToStreams(iStreamID, 1, "", "")
                            else:
                                addFileNameToStreams(strRawName, 1, "", "")
                    else:
                        sys.stderr.write(" Error: Header 2 not found in stream %d\n" % iStreamCounter)
                        config.EXIT_CODE = 17
                        return

                if (not config.ARGS.quiet):
                    print(STR_SEP)
                # -----------------------------------------------------------------

            elif (oleBlock["type"] == 5): # Root Entry
                if (not config.ARGS.quiet):
                    print(" Root Entry\n --------------------")
                    printBlock(strRawName, oleBlock)
                if (config.ARGS.htmlrep): # ...implies config.ARGS.outdir
                    HTTP_REPORT.setOLE(oleBlock)
                if (not config.ARGS.quiet):
                    print(STR_SEP)

            iStreamCounter += 1

        currentBlock = nextBlock(thumbsDB, SATblocks, currentBlock, tDB_endian)

    if isCatalogOutOfSequence():
        sys.stderr.write(" Info: %s - Catalog index number out of usual sequence\n" % infile)

    if isStreamsOutOfSequence():
        sys.stderr.write(" Info: %s - Stream index number out of usual sequence\n" % infile)

    astrStats = extractStats(config.ARGS.outdir)
    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (config.ARGS.htmlrep): # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks): # ...implies config.ARGS.outdir
          strSubDir = config.THUMBS_SUBDIR
        HTTP_REPORT.flush(astrStats, strSubDir)

    if (config.ARGS.outdir != None):
        iCountCatalogEntries = countCatalogEntry()
        if (iCountCatalogEntries > 0):
            if (iCountCatalogEntries != countThumbnails()):
                sys.stderr.write(" Warning: %s - Counts (Catalog != Extracted)\n" % infile)
            else:
                sys.stderr.write(" Info: %s - Counts (Catalog == Extracted)\n" % infile)
        else:
            sys.stderr.write(" Info: %s - No Catalog\n" % infile)


def processThumbsTypeCMMM(infile, thumbsDB, thumbsDBsize):
    global HTTP_REPORT

    # tDB_endian = "<" ALWAYS Little???

    if (thumbsDBsize < 24):
        sys.stderr.write(" Warning: %s too small to process header\n" % infile)
        return

    # Header...
    thumbsDB.seek(0x04)
    tDB_formatVer        = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheType        = unpack("<L", thumbsDB.read(4))[0]
    if (tDB_formatVer > config.TC_FORMAT_TYPE.get("Windows 8")):
        thumbsDB.read(4) # Skip an integer size
    tDB_cacheOff1st      = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheOff1stAvail = unpack("<L", thumbsDB.read(4))[0]
    tDB_cacheCount       = None # Cache Count not available above Windows 8 v2
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
    if (config.ARGS.htmlrep): # ...implies config.ARGS.outdir
        HTTP_REPORT.setCMMM(strFormatType, strCacheType, tDB_cacheOff1st, tDB_cacheOff1stAvail, tDB_cacheCount)

    # Cache...
    iOffset = tDB_cacheOff1st
    iCacheCounter = 1
    while (True):
        if (thumbsDBsize < (iOffset + 48)):
            sys.stderr.write(" Warning: Remaining cache entry %d too small to process\n" % iCacheCounter)
            break

        thumbsDB.seek(iOffset)
        tDB_sig = thumbsDB.read(4)
        if (tDB_sig != config.THUMBS_SIG_CMMM):
            break
        tDB_size = unpack("<L", thumbsDB.read(4))[0]
        tDB_hash = unpack("<Q", thumbsDB.read(8))[0]
        iOffset += 16

        tDB_ext = None # File Extension not available above Windows Vista
        if (tDB_formatVer == config.TC_FORMAT_TYPE.get("Windows Vista")):
            tDB_ext = thumbsDB.read(8) # 2 bytes * 4 wchar_t characters
            iOffset += 8

        tDB_idSize   = unpack("<L",  thumbsDB.read(4))[0]
        tDB_padSize  = unpack("<L",  thumbsDB.read(4))[0]
        tDB_dataSize = unpack("<L",  thumbsDB.read(4))[0]
        iOffset += 12

        tDB_width  = None # Image Width  not available below Windows 8
        tDB_height = None # Image Height not available below Windows 8
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
            continue # ...no ID, so probably empty last entry

        strHash = format(tDB_hash, 'x')

        strExt = None
        # Try the given Vista ext...
        if (tDB_ext != None):
            strExt = decodeBytes(tDB_ext)
        if (tDB_dataSize > 0):
            # Detect data type ext by magic bytes...
            tupleImageTypes = (
                (bytearray(b'\x42\x4D'), "bmp"),                        # BM
                (bytearray(b'\xFF\xD8\xFF\xE0'), "jpg")                 # ....
                (bytearray(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'), "png") # .PNG\n\r\sub\r
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
                if (strFileName != None and config.ARGS.symlinks): # ...implies config.ARGS.outdir
                        bHasSymName = True
                        strTarget = config.ARGS.outdir + config.THUMBS_SUBDIR + "/" + strCleanFileName + "." + strExt
                        symlink_force(strTarget, config.ARGS.outdir + strFileName)
                        if (config.EXIT_CODE > 0):
                                return
                        fileURL = open(config.ARGS.outdir + config.THUMBS_FILE_URLS, "a+")
                        fileURL.write(strTarget + " => " + strFileName + "\n")
                        fileURL.close()

                # Add a "catalog" entry if Cache ID match in ESEDB...
                addCatalogEntry(1, dictESEDB["DATEM"], strFileName)

            # Write data to filename...
            if (config.ARGS.outdir != None):
                strFileName = getFileName(-1, strCleanFileName, strExt, bHasSymName, 2)
                fileImg = open(config.ARGS.outdir + strFileName, "wb")
                fileImg.write(tDB_data)
                fileImg.close()
            else: # Not extracting...
                addFileNameToStreams(strID, 2, "")

        # End of Loop
        iCacheCounter += 1

        if (not config.ARGS.quiet):
            print(STR_SEP)

        # Check End of File...
        if (thumbsDBsize <= iOffset):
            break

    astrStats = extractStats(config.ARGS.outdir)
    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (config.ARGS.htmlrep): # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks): # ...implies config.ARGS.outdir
          strSubDir = config.THUMBS_SUBDIR
        HTTP_REPORT.flush(astrStats, strSubDir)


def processThumbsTypeIMMM(infile, thumbsDB, thumbsDBsize):
    global HTTP_REPORT

    # tDB_endian = "<" ALWAYS

    if (thumbsDBsize < 24):
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

        # TODO: DO MORE!!!

        # End of Loop
        iOffset = iOffFlags + 24
        iEntryCounter += 1

    astrStats = extractStats(config.ARGS.outdir)
    if (not config.ARGS.quiet):
        print(" Summary:")
        if (astrStats != None):
            for strStat in astrStats:
                print("   " + strStat)
        else:
            print("   No Stats!")
    if (config.ARGS.htmlrep): # ...implies config.ARGS.outdir
        strSubDir = "."
        if (config.ARGS.symlinks): # ...implies config.ARGS.outdir
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
    thumbsDBdata = thumbsDB.read(0x08)
    if   (thumbsDBdata[0x00:0x08] == config.THUMBS_SIG_OLE):
        thumbsDBtype = config.THUMBS_TYPE_OLE
    elif (thumbsDBdata[0x00:0x08] == config.THUMBS_SIG_OLEB):
        thumbsDBtype = config.THUMBS_TYPE_OLE
    elif (thumbsDBdata[0x00:0x04] == config.THUMBS_SIG_CMMM):
        thumbsDBtype = config.THUMBS_TYPE_CMMM
    elif (thumbsDBdata[0x00:0x04] == config.THUMBS_SIG_IMMM):
        thumbsDBtype = config.THUMBS_TYPE_IMMM
    else: # ...Header Signature not found...
        if (bProcessError):
            sys.stderr.write(" Error: Header Signature not found in %s\n" % infile)
            config.EXIT_CODE = 12
        return # ..always return here

    # Initialize optional HTML report...
    if (config.ARGS.htmlrep): # ...implies config.ARGS.outdir
        HTTP_REPORT = report.HttpReport(getEncoding(), infile, config.ARGS.outdir,
                                STR_VERSION,
                                thumbsDBtype, thumbsDBsize, thumbsDBmd5)

    if (thumbsDBtype == config.THUMBS_TYPE_OLE):
        processThumbsTypeOLE(infile, thumbsDB, thumbsDBsize)
    elif (thumbsDBtype == config.THUMBS_TYPE_CMMM):
        processThumbsTypeCMMM(infile, thumbsDB, thumbsDBsize)
    elif (thumbsDBtype == config.THUMBS_TYPE_IMMM):
        processThumbsTypeIMMM(infile, thumbsDB, thumbsDBsize)
    else: # ...should never hit this as it's caught above, thumbsDBtype should always be set properly
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
        sys.stderr.write(" Info: FS - Detected a Windows Vista-like partition\n")
        with os.scandir(strUserBaseDirVista) as iterDirs:
            for entryUserDir in iterDirs:
                if not entryUserDir.is_dir():
                    continue
                userThumbsDir = os.path.join(entryUserDir.path, config.OS_WIN_THUMBCACHE_DIR)
                if not os.path.exists(userThumbsDir): # ...NOT exists?
                    print(" Warning: Skipping %s - does not contain %s\n" % (entryUserDir.path, config.OS_WIN_THUMBCACHE_DIR))
                else:
                    processDirectory(userThumbsDir)
        return
    elif os.path.isdir(strUserBaseDirXP):
        sys.stderr.write(" Info: FS - Detected a Windows XP-like partition\n")
    else:
        sys.stderr.write(" Info: FS - Unknown partition\n")

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

    if (config.ARGS.mode == None):
      config.ARGS.mode = "f"

    strError = " Error: "

    # Test Input File parameter...
    if not os.path.exists(config.ARGS.infile): # ...NOT exists?
        sys.stderr.write("%s%s does not exist\n" % (strError, config.ARGS.infile))
        sys.exit(10)
    if (config.ARGS.mode == "f"): # Traditional Mode...
        if not os.path.isfile(config.ARGS.infile): # ...NOT a file?
            sys.stderr.write("%s%s not a file\n" % (strError, config.ARGS.infile))
            sys.exit(10)
    else: # Directory, Recursive Directory, or Automatic Mode...
        if not os.path.isdir(config.ARGS.infile): # ...NOT a directory?
            sys.stderr.write("%s%s not a directory\n" % (strError, config.ARGS.infile))
            sys.exit(10)
        # Add ending '/' as needed...
        if not config.ARGS.infile.endswith('/'):
            config.ARGS.infile += "/"
    if not os.access(config.ARGS.infile, os.R_OK): # ...NOT readable?
        sys.stderr.write("%s%s not readable\n" % (strError, config.ARGS.infile))
        sys.exit(10)

    # Test Output Directory parameter...
    if (config.ARGS.outdir != None):
        # Testing DIR parameter...
        if not os.path.exists(config.ARGS.outdir): # ...NOT exists?
            try:
                os.mkdir(config.ARGS.outdir) # ...make it
                sys.stderr.write(" Info: %s was created\n" % config.ARGS.outdir)
            except EnvironmentError as e:
                sys.stderr.write("%sCannot create %s\n" % (strError, config.ARGS.outdir))
                sys.exit(11)
        else: # ...exists...
            if not os.path.isdir(config.ARGS.outdir): # ...NOT a directory?
                sys.stderr.write("%s%s is not a directory\n" % (strError, config.ARGS.outdir))
                sys.exit(11)
            elif not os.access(config.ARGS.outdir, os.W_OK): # ...NOT writable?
                sys.stderr.write("%s%s not writable\n" % (strError, config.ARGS.outdir))
                sys.exit(11)
        # Add ending '/' as needed...
        if not config.ARGS.outdir.endswith('/'):
            config.ARGS.outdir += "/"

        # Remove existing URL file...
        if os.path.exists(config.ARGS.outdir + config.THUMBS_FILE_URLS):
            os.remove(config.ARGS.outdir + config.THUMBS_FILE_URLS)

    # Correct MD5 Force parameter...
    if (config.ARGS.md5force) and (config.ARGS.md5never):
        config.ARGS.md5force = False

    # Test EDB file parameter...
    bEDBErrorOut = True
    bEDBFileGood = False
    strEDBFileReport = config.ARGS.edbfile
    strErrorReport = strError
    if (config.ARGS.mode == "a" and config.ARGS.edbfile == None):
        bEDBErrorOut = False
        strErrorReport = " Warning: "
        strEDBFileReport = "Default ESEDB"
        # Try Vista+ first...
        strEDBFile = os.path.join(config.ARGS.infile, config.OS_WIN_ESEDB_VISTA + config.OS_WIN_COMMON)
        if not os.path.exists(strEDBFile): # ...NOT exists?
            # Fallback to XP...
            strEDBFile = os.path.join(config.ARGS.infile, config.OS_WIN_USERS_XP + config.OS_WIN_ESEDB_XP + config.OS_WIN_COMMON)
        config.ARGS.edbfile = strEDBFile
    if (config.ARGS.edbfile != None):
        # Testing EDBFILE parameter...
        if not os.path.exists(config.ARGS.edbfile): # ...NOT exists?
            sys.stderr.write("%s%s does not exist\n" % (strErrorReport, strEDBFileReport))
            if bEDBErrorOut: sys.exit(19)
        elif not os.path.isfile(config.ARGS.edbfile): # ...NOT a file?
            sys.stderr.write("%s%s is not a file\n" % (strErrorReport, strEDBFileReport))
            if bEDBErrorOut: sys.exit(19)
        elif not os.access(config.ARGS.edbfile, os.R_OK): # ...NOT readable?
            sys.stderr.write("%s%s not readable\n" % (strErrorReport, strEDBFileReport))
            if bEDBErrorOut: sys.exit(19)
        else:
            bEDBFileGood = True

        if bEDBFileGood:
            prepareEDB()
        else:
            sys.stderr.write(strErrorReport + "Skipping any ESE DB processing\n")

    if (config.EXIT_CODE == 0):
        # Initialize processing for output...
        if (config.ARGS.outdir != None):

            # Initializing PIL library for Type 1 image extraction...
            PIL_FOUND = True
            try:
                from PIL import Image
            except ImportError:
                PIL_FOUND = False
                sys.stderr.write(" Warning: Cannot find PIL Package Image module.\n" +
                                 "          Vinetto will only extract Type 2 thumbnails.\n")
            if (PIL_FOUND == True):
                IMAGE_TYPE_1_HEADER   = open(resource_filename("vinetto", "data/header"), "rb").read()
                IMAGE_TYPE_1_QUANTIZE = open(resource_filename("vinetto", "data/quantization"), "rb").read()
                IMAGE_TYPE_1_HUFFMAN  = open(resource_filename("vinetto", "data/huffman"), "rb").read()

            # Initializing Symbolic (soft) File Links...
            setupSymLink()

    if (config.EXIT_CODE == 0):
        if (config.ARGS.mode == "f"): # Traditional Mode
            processThumbFile(config.ARGS.infile)
        elif (config.ARGS.mode == "d"): # Directory Mode
            processDirectory(config.ARGS.infile)
        elif (config.ARGS.mode == "r"): # Recursive Directory Mode
            processRecursiveDirectory()
        elif (config.ARGS.mode == "a"): # Automatic Mode - File System
            processFileSystem()
        else: # Unknown Mode
            sys.stderr.write("%sUnknown mode (%s) to process %s\n" % (strError, config.ARGS.mode, config.ARGS.infile))
            config.EXIT_CODE = 10

    if (config.ESEDB_FILE != None):
        config.ESEDB_FILE.close()

    if (config.EXIT_CODE > 0):
        sys.exit(config.EXIT_CODE)
